"""
Type Analysis Module for VERITAS Demo

This module generates type signatures using Gemini 2.5 Pro LLM.
It analyzes Ghidra decompiled code and assembly to infer correct
function signatures (return type, argument count, argument types).

Reference: TypeComparison/epytview/src/typeanalysis.py
"""

import json
import re
from pathlib import Path
from typing import Dict, Optional

# Try to import Google's generative AI library
try:
    import google.generativeai as genai
    HAS_GEMINI = True
except ImportError:
    HAS_GEMINI = False
    print("[TypeAnalysis] Warning: google-generativeai not installed.")
    print("[TypeAnalysis] Install with: pip install google-generativeai")


class GeminiTypeAnalyzer:
    """
    Analyzes binary functions to infer correct type signatures using Gemini LLM.
    """
    
    def __init__(
        self,
        api_key: str,
        model_name: str = "gemini-2.5-pro",
        temperature: float = 0.3
    ):
        """
        Initialize the Gemini type analyzer.
        
        Args:
            api_key: Google API key for Gemini
            model_name: Gemini model to use (default: gemini-2.5-pro)
            temperature: Sampling temperature (default: 0.3 for consistency)
        """
        if not HAS_GEMINI:
            raise ImportError("google-generativeai is required. pip install google-generativeai")
        
        self.api_key = api_key
        self.model_name = model_name
        self.temperature = temperature
        
        # Configure Gemini
        genai.configure(api_key=api_key)
        
        generation_config = {
            "temperature": temperature,
        }
        
        self.model = genai.GenerativeModel(
            model_name=model_name,
            generation_config=generation_config
        )
    
    def analyze_signature(
        self,
        ghidra_code: str,
        asm: str,
        type_constraints: Optional[Dict] = None
    ) -> Dict:
        """
        Analyze function signature using Gemini.
        
        Args:
            ghidra_code: Ghidra decompiled pseudocode
            asm: Assembly instructions
            type_constraints: Optional TypeForge/Typehoon constraints
            
        Returns:
            Dict with {arg_count, arg_types, return_type} or None on failure
        """
        prompt = self._build_signature_prompt(ghidra_code, asm, type_constraints)
        
        try:
            response = self.model.generate_content(prompt)
            
            # Extract text from response
            if not hasattr(response, "candidates") or not response.candidates:
                print("[TypeAnalysis] No candidates returned from Gemini")
                return None
            
            candidate = response.candidates[0]
            if not candidate or not candidate.content.parts:
                print("[TypeAnalysis] Empty response from Gemini")
                return None
            
            text_parts = []
            for part in candidate.content.parts:
                if hasattr(part, "text") and part.text:
                    text_parts.append(part.text)
            
            if not text_parts:
                print("[TypeAnalysis] No text content in response")
                return None
            
            raw_output = "\n".join(text_parts)
            
            # Parse the JSON response
            return self._parse_signature_response(raw_output)
            
        except Exception as e:
            print(f"[TypeAnalysis] Error calling Gemini: {e}")
            return None
    
    def _build_signature_prompt(
        self,
        ghidra_code: str,
        asm: str,
        type_constraints: Optional[Dict]
    ) -> str:
        """Build the prompt for signature analysis."""
        
        prompt = """You are an expert reverse engineer analyzing a decompiled function.
Your task is to infer the CORRECT function signature (return type, argument count, argument types).

IMPORTANT RULES:
1. Ghidra's decompiled output may be WRONG - especially return types (often says void when it should return a value)
2. Assembly is GROUND TRUTH - check what's in return registers before RET
3. If function COMPUTES a value, it likely RETURNS it
4. Type constraints from static analysis are helpful but may also be wrong

RETURN TYPE INFERENCE:
• If xmm0/xmm1 has value before RET → return type is float/double
• If eax/rax has value before RET → return type is int/long
• If function computes sum/average/etc → it MUST return the result
• "xor eax, eax" followed by RET is "return 0", NOT void!

PARAMETER INFERENCE:
• Check how rdi, rsi, rdx, rcx, r8, r9 are used (x86-64 calling convention)
• For floating-point: xmm0-xmm7 are used for float/double args
• Count actual parameters used, not what Ghidra shows

"""
        
        if type_constraints:
            prompt += f"""
TYPE CONSTRAINTS (from static analysis - use as hints, but verify against ASM):
{json.dumps(type_constraints, indent=2)[:2000]}

"""
        
        prompt += f"""
GHIDRA DECOMPILED CODE (may be incorrect):
```c
{ghidra_code}
```

ASSEMBLY INSTRUCTIONS (ground truth):
```asm
{asm[:5000]}
```

OUTPUT FORMAT:
You MUST output ONLY a valid JSON object with this exact structure:
{{
    "arg_count": <number>,
    "arg_types": [<list of type strings>],
    "return_type": "<type string>"
}}

Use standard C/C++ types like: int, float, double, void, char*, int*, long, size_t, etc.
For C++ containers: std::vector<int>, std::string, etc.

ONLY output the JSON object, nothing else.
"""
        return prompt
    
    def _parse_signature_response(self, raw_output: str) -> Optional[Dict]:
        """Parse the JSON response from Gemini."""
        # Clean up the response
        raw_output = raw_output.strip()
        
        # Remove markdown code fences if present
        raw_output = re.sub(r'^```[a-zA-Z]*\s*', '', raw_output)
        raw_output = re.sub(r'```$', '', raw_output.strip())
        raw_output = raw_output.strip()
        
        try:
            parsed = json.loads(raw_output)
            
            # Validate expected fields
            if not isinstance(parsed, dict):
                print("[TypeAnalysis] Response is not a dict")
                return None
            
            # Ensure required fields exist
            result = {
                "arg_count": parsed.get("arg_count", 0),
                "arg_types": parsed.get("arg_types", []),
                "return_type": parsed.get("return_type", "unknown")
            }
            
            # Validate types
            if not isinstance(result["arg_count"], int):
                result["arg_count"] = int(result["arg_count"]) if result["arg_count"] else 0
            
            if not isinstance(result["arg_types"], list):
                result["arg_types"] = []
            
            if not isinstance(result["return_type"], str):
                result["return_type"] = str(result["return_type"])
            
            return result
            
        except json.JSONDecodeError as e:
            print(f"[TypeAnalysis] JSON parse error: {e}")
            print(f"[TypeAnalysis] Raw output: {raw_output[:500]}")
            return None


def format_gemini_signature_for_prompt(signature: Dict) -> str:
    """
    Format a Gemini-analyzed signature for inclusion in decompilation prompts.
    
    Args:
        signature: Dict with {arg_count, arg_types, return_type}
        
    Returns:
        Formatted string for LLM prompt
    """
    if not signature:
        return ""
    
    arg_types = signature.get('arg_types', [])
    return_type = signature.get('return_type', 'unknown')
    arg_count = signature.get('arg_count', len(arg_types))
    
    lines = [
        "═══════════════════════════════════════════════════════════════════════════════",
        "GEMINI-VERIFIED FUNCTION SIGNATURE (MANDATORY - YOU MUST USE THESE EXACT TYPES)",
        "═══════════════════════════════════════════════════════════════════════════════",
        "",
        f"Return Type: {return_type}",
        f"Number of Arguments: {arg_count}",
        "Argument Types:"
    ]
    
    for i, arg_type in enumerate(arg_types):
        lines.append(f"  Argument {i+1}: {arg_type}")
    
    lines.extend([
        "",
        "⚠️ CRITICAL: These types have been verified by Gemini analysis and are CORRECT.",
        "⚠️ You MUST use these EXACT types in your output code.",
        "⚠️ DO NOT change the return type, argument count, or argument types.",
        "⚠️ If Ghidra/decompiler says different types, IGNORE Ghidra - USE GEMINI TYPES.",
        "═══════════════════════════════════════════════════════════════════════════════"
    ])
    
    return "\n".join(lines)


def create_type_analyzer(
    provider: str,
    api_key: str,
    model_name: Optional[str] = None
) -> Optional[GeminiTypeAnalyzer]:
    """
    Factory function to create a type analyzer.
    
    Args:
        provider: LLM provider (currently only "gemini" supported)
        api_key: API key for the provider
        model_name: Model name (default: gemini-2.5-pro for Gemini)
        
    Returns:
        GeminiTypeAnalyzer instance or None if provider not supported
    """
    if provider.lower() == "gemini":
        model = model_name or "gemini-2.5-pro"
        return GeminiTypeAnalyzer(api_key=api_key, model_name=model)
    else:
        print(f"[TypeAnalysis] Unsupported provider: {provider}")
        return None
