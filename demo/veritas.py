#!/usr/bin/env python3
"""
VERITAS Demo - Single Executable Decompilation Pipeline

This is a standalone demo that processes a single executable binary through
the complete VERITAS decompilation pipeline:

1. Ghidra Analysis - Extract pseudocode and assembly
2. Type Constraint Generation - TypeForge + Typehoon analysis
3. Type Signature Analysis - Gemini 2.5 Pro type inference
4. LLM Decompilation - Generate source code from pseudocode
5. Static Repair - Fix compilation errors
6. Semantic Verification - VexHelix equivalence checking
7. Semantic Repair - Fix semantic divergences

Usage:
    python veritas.py --executable /path/to/binary \
                      --gemini_provider gemini \
                      --gemini_model_name gemini-2.5-pro \
                      --gemini_api_key YOUR_API_KEY \
                      [--language c|cpp] \
                      [--function_name func0] \
                      [--opt O0|O1|O2|O3] \
                      [--output_dir /path/to/output] \
                      [--vexhelix_url http://127.0.0.1:8001]

Author: VERITAS Team
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

# Add parent directory to path for VERITAS utils imports
DEMO_DIR = Path(__file__).resolve().parent
VERITAS_ROOT = DEMO_DIR.parent
sys.path.insert(0, str(VERITAS_ROOT))
sys.path.insert(0, str(DEMO_DIR))

# Import from VERITAS utils (parent directory)
from utils.compile import Compiler, OptimizationLevel
from utils.ghidra import Ghidra
from utils.clean_errors import ErrorNormalizer

# Import demo utilities (local demo_utils directory)
from typeanalysis import GeminiTypeAnalyzer, format_gemini_signature_for_prompt, create_type_analyzer
from demo_utils.typeforge import acquire_typeforge_constraints, load_typeforge_constraints, format_typeforge_for_prompt
from demo_utils.typehoon import extract_typehoon_constraints, format_typehoon_for_prompt


# =============================================================================
# CONFIGURATION
# =============================================================================

# VexHelix API defaults
DEFAULT_VEXHELIX_URL = "http://127.0.0.1:8001"
VEXHELIX_TIMEOUT = 180
VEXHELIX_LOOP_BOUND = 5
VEXHELIX_RETRIES = 3

# Repair configuration
MAX_REPAIR_ITERATIONS = 5
MAX_STATIC_REPAIR_PER_CYCLE = 3
MAX_STAGNANT_ITERATIONS = 3

# Context limits
MAX_ERROR_CHARS = 2000
MAX_ASM_CHARS = 8000
MAX_CODE_CHARS = 12000
MAX_TYPE_CONSTRAINT_CHARS = 3000

# Load config.yaml from VERITAS root
CONFIG_PATH = VERITAS_ROOT / "config.yaml"
try:
    import yaml
    with open(CONFIG_PATH, "r") as f:
        VERITAS_CONFIG = yaml.safe_load(f)
except Exception as e:
    print(f"[Warning] Could not load config.yaml: {e}")
    VERITAS_CONFIG = {}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class VexHelixResult:
    """Result from VexHelix verification."""
    success: bool
    status: Optional[str]  # "equivalent", "different", "error", "timeout"
    equivalent: Optional[bool]
    divergences: Optional[List[Dict]]
    statistics: Optional[Dict]
    error_message: Optional[str]
    compilation_error: Optional[str]


@dataclass
class DecompilationResult:
    """Result from the decompilation pipeline."""
    success: bool
    original_ghidra: str
    optimized_code: str
    gemini_signature: Optional[Dict]
    type_constraints: Optional[Dict]
    stats: Dict = field(default_factory=dict)
    error_message: Optional[str] = None


# =============================================================================
# GEMINI LLM INTERFACE
# =============================================================================

class GeminiInterface:
    """Interface for Google Gemini LLM for code generation."""
    
    def __init__(
        self,
        api_key: str,
        model_name: str = "gemini-2.5-pro",
        temperature: float = 0.3
    ):
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            
            generation_config = {
                "temperature": temperature,
            }
            
            self.model = genai.GenerativeModel(
                model_name=model_name,
                generation_config=generation_config
            )
            self.model_name = model_name
        except ImportError:
            raise ImportError("Please install google-generativeai: pip install google-generativeai")
    
    def generate(self, prompt: str) -> str:
        """Generate response using Gemini API."""
        try:
            response = self.model.generate_content(prompt)
            
            if not hasattr(response, "candidates") or not response.candidates:
                print("[Gemini] No candidates returned, retrying...")
                response = self.model.generate_content(prompt)
            
            if not hasattr(response, "candidates") or not response.candidates:
                return ""
            
            candidate = response.candidates[0]
            if not candidate or not candidate.content.parts:
                return ""
            
            text_parts = []
            for part in candidate.content.parts:
                if hasattr(part, "text") and part.text:
                    text_parts.append(part.text)
            
            if not text_parts:
                return ""
            
            return self._clean_output("\n".join(text_parts))
            
        except Exception as e:
            print(f"[Gemini] Error: {e}")
            return ""
    
    def _clean_output(self, code: str) -> str:
        """Remove Markdown code fences from LLM output."""
        code = re.sub(r"^```[a-zA-Z0-9]*\s*", "", code.strip())
        code = re.sub(r"```$", "", code.strip())
        return code.strip()


# =============================================================================
# ASM VERIFICATION PROTOCOL
# =============================================================================

ASM_VERIFICATION_PROTOCOL = """
═══════════════════════════════════════════════════════════════════════════════
ASM-BASED VERIFICATION PROTOCOL - FOR C ASM ONLY! (STRICT OVERRIDE RULES)
═══════════════════════════════════════════════════════════════════════════════
You MUST validate Ghidra's output against the ASM instructions. Ghidra frequently misidentifies signedness and constness.
Apply the following 4 heuristics to the ASM. If they contradict Ghidra, THE ASM WINS.

1. SIGNED vs UNSIGNED MISMATCH (The "Jump" Rule)
   • SIGNED: If you see `jg`, `jge`, `jl`, `jle`, `cmovg`, `cmovl`, `idiv`, `cvtsi2ss` → The type is SIGNED.
   • UNSIGNED: If you see `ja`, `jae`, `jb`, `jbe`, `div`, `shl`, `shr` → The type is UNSIGNED.

2. CONST vs NON-CONST (The "Write" Rule)
   • NON-CONST: If you see `mov [reg], val` or `mov [reg + off], val` using the argument's register.
   • CONST: If the pointer is ONLY used in `mov reg, [arg]` (reads).

3. ARRAY vs POINTER (The "Addressing" Rule)
   • ARRAY: Look for SIB addressing: `(%rdi,%rax,4)` or `[rdi + rax*4]`.
   • POINTER: Look for pointer walking: `add $4, %rdi` followed by `mov ... (%rdi)`.

4. VOID vs VALUE (The "Dead Register" Rule)
   • NOT VOID: If `eax`, `rax`, or `xmm0` are written to before `ret`.
   • BOOLEAN: If return values are strictly 0 and 1, prefer `bool` over `int`.
"""


# =============================================================================
# PROMPT GENERATION
# =============================================================================

def get_system_prompt():
    """Get the base system prompt for decompilation."""
    if VERITAS_CONFIG.get("prompts", {}).get("system_prompt"):
        return VERITAS_CONFIG["prompts"]["system_prompt"]
    
    return """You are given decompiler-generated pseudocode and compiler output for a C/C++ function.
Your task is to produce Linux-compilable source code that matches the original compiled behavior.

IMPORTANT: Decompiler output is approximate. It may be correct 50-70% of the time.

Common decompiler reconstruction issues:
- SIGNATURE ISSUES: wrong return type (void vs int/float), wrong param count, wrong param types
- TYPE ISSUES: pointer vs integer confusion, signed vs unsigned, float vs int
- CONTROL FLOW ISSUES: empty loop bodies, wrong bounds, missing branches

RETURN TYPE INFERENCE:
• If floating-point register is set before function exit → return type is float/double
• If integer return register is set before function exit → return type is int/long
• If function COMPUTES a value → it MUST RETURN that value

STRICT RULES:
- Do NOT change the function name
- Output ONLY the corrected source code (C or C++ as appropriate)
- Do NOT include main() unless it exists in the provided pseudocode
"""


def get_initial_prompt(
    ghidra_code: str,
    asm: str,
    function_summary: str,
    type_constraints: Optional[Dict],
    signature_analysis: str,
    language: str
) -> str:
    """Generate the initial decompilation prompt."""
    
    truncated_asm = asm[:MAX_ASM_CHARS] if asm else ""
    if asm and len(asm) > MAX_ASM_CHARS:
        truncated_asm += "\n; ... (truncated)"
    
    prompt = f"""{get_system_prompt()}

═══════════════════════════════════════════════════════════════════════════════
COMPILER OUTPUT (GROUND TRUTH - this is what the code ACTUALLY does):
═══════════════════════════════════════════════════════════════════════════════
```
{truncated_asm}
```

═══════════════════════════════════════════════════════════════════════════════
DECOMPILER PSEUDOCODE (MAY BE INCORRECT - use as rough guide only):
═══════════════════════════════════════════════════════════════════════════════
```{language}
{ghidra_code}
```

Function Summary: {function_summary}
"""
    
    # Add Gemini signature if available
    if signature_analysis:
        prompt += f"\n\n{signature_analysis}\n"
    
    # Add ASM verification protocol for C
    if language.lower() == 'c':
        prompt += f"\n{ASM_VERIFICATION_PROTOCOL}\n"
    
    # Add type constraints if available
    if type_constraints:
        type_str = format_type_constraints(type_constraints)
        if type_str:
            prompt += f"\n\n{type_str}"
    
    return prompt


def get_static_repair_prompt(
    code: str,
    compilation_errors: str,
    function_summary: str,
    type_constraints: Optional[Dict],
    signature_analysis: str,
    language: str,
    asm: str = ""
) -> str:
    """Generate the static repair prompt for compilation errors."""
    
    truncated_errors = compilation_errors[:MAX_ERROR_CHARS]
    if len(compilation_errors) > MAX_ERROR_CHARS:
        truncated_errors += "\n... (error truncated)"
    
    truncated_code = code[:MAX_CODE_CHARS]
    if len(code) > MAX_CODE_CHARS:
        truncated_code += "\n// ... (code truncated)"
    
    truncated_asm = asm[:MAX_ASM_CHARS] if asm else ""
    
    prompt = f"""You are fixing compilation errors in reconstructed C/C++ code.

Language: {language}
Summary: {function_summary}

Current Code:
```{language}
{truncated_code}
```

Compilation Errors:
{truncated_errors}

Please provide the corrected {language.upper()} code.
"""
    
    # Add Gemini signature
    if signature_analysis:
        prompt += f"\n\n{signature_analysis}\n\n⚠️ CRITICAL: When fixing, YOU MUST PRESERVE the Gemini signature types!"
    
    # Add ASM for context
    if truncated_asm:
        prompt += f"\n\nCOMPILER OUTPUT (ground truth):\n```\n{truncated_asm}\n```"
    
    # Add ASM verification protocol for C
    if language.lower() == 'c':
        prompt += f"\n{ASM_VERIFICATION_PROTOCOL}"
    
    # Add type constraints
    if type_constraints:
        type_str = format_type_constraints(type_constraints)
        if type_str:
            prompt += f"\n\n{type_str}\n\nUse these type constraints to help fix type-related errors."
    
    return prompt


def get_semantic_repair_prompt(
    original_asm: str,
    original_ghidra: str,
    current_code: str,
    function_summary: str,
    vexhelix_result: VexHelixResult,
    type_constraints: Optional[Dict],
    signature_analysis: str,
    language: str
) -> str:
    """Generate the semantic repair prompt."""
    
    truncated_asm = original_asm[:MAX_ASM_CHARS] if original_asm else ""
    truncated_ghidra = original_ghidra[:MAX_CODE_CHARS] if original_ghidra else ""
    truncated_current = current_code[:MAX_CODE_CHARS] if current_code else ""
    
    prompt = f"""You are fixing reconstructed code that produces WRONG outputs. 
The semantic verifier found behavioral differences.

═══════════════════════════════════════════════════════════════════════════════
COMPILER OUTPUT (GROUND TRUTH):
═══════════════════════════════════════════════════════════════════════════════
```
{truncated_asm}
```

═══════════════════════════════════════════════════════════════════════════════
DECOMPILER PSEUDOCODE (UNRELIABLE):
═══════════════════════════════════════════════════════════════════════════════
```{language}
{truncated_ghidra}
```

═══════════════════════════════════════════════════════════════════════════════
YOUR CURRENT CODE (WRONG - produces incorrect output):
═══════════════════════════════════════════════════════════════════════════════
```{language}
{truncated_current}
```

Function Summary: {function_summary}

VERIFICATION: DIFFERENT (your code doesn't match expected behavior)
"""
    
    # Add type constraints
    if type_constraints:
        type_str = format_type_constraints(type_constraints)
        if type_str:
            prompt += f"\n\n{type_str}"
    
    # Add Gemini signature
    if signature_analysis:
        prompt += f"\n\n{signature_analysis}\n\n⚠️ CRITICAL: You MUST use these EXACT types!"
    
    # Add ASM verification protocol for C
    if language.lower() == 'c':
        prompt += f"\n{ASM_VERIFICATION_PROTOCOL}"
    
    # Format divergences
    if vexhelix_result.divergences:
        prompt += "\n\n═══════════════════════════════════════════════════════════════════════════════\n"
        prompt += "COUNTEREXAMPLES (inputs where your code gives WRONG answer):\n"
        prompt += "═══════════════════════════════════════════════════════════════════════════════\n"
        for i, div in enumerate(vexhelix_result.divergences[:5]):
            prompt += f"\nTest case {i+1}:\n"
            if div.get('inputs'):
                inputs_str = ", ".join([f"{inp.get('name', 'arg')}={inp.get('value', '?')}" for inp in div['inputs']])
                prompt += f"  Inputs: {inputs_str}\n"
            if div.get('orig_output'):
                orig = div['orig_output']
                prompt += f"  ✓ Expected (from binary): {orig.get('value', '?')}\n"
            if div.get('dec_output'):
                dec = div['dec_output']
                prompt += f"  ✗ Your output: {dec.get('value', '?')}\n"
    
    prompt += """

═══════════════════════════════════════════════════════════════════════════════
YOUR TASK: Fix the code to match expected behavior
═══════════════════════════════════════════════════════════════════════════════

Steps:
1. CHECK GEMINI SIGNATURE FIRST - You MUST use the EXACT types specified!
2. CHECK RETURN TYPE - if a value is prepared for return, function returns a value!
3. If function COMPUTES something, it MUST RETURN it
4. Check COUNTEREXAMPLES - understand WHY your code gives wrong output

Output ONLY the corrected function code. No explanations."""
    
    return prompt


def format_type_constraints(type_constraints: Dict) -> str:
    """Format type constraints for prompt inclusion."""
    if not type_constraints:
        return ""
    
    # Check if it's TypeForge format (list of constraints)
    if isinstance(type_constraints, list):
        return format_typeforge_for_prompt(type_constraints)
    
    # Check if it's Typehoon format (dict with success field)
    if isinstance(type_constraints, dict) and "success" in type_constraints:
        return format_typehoon_for_prompt(type_constraints)
    
    # Fallback: JSON dump
    return f"TYPE CONSTRAINTS:\n{json.dumps(type_constraints, indent=2)[:MAX_TYPE_CONSTRAINT_CHARS]}"


# =============================================================================
# VEXHELIX API
# =============================================================================

def check_vexhelix_health(vexhelix_url: str) -> bool:
    """Check if VexHelix API is available."""
    try:
        response = requests.get(f"{vexhelix_url}/health", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"[VexHelix] Health check: {data.get('status', 'unknown')}")
            return data.get('status') == 'healthy'
        return False
    except Exception as e:
        print(f"[VexHelix] Health check failed: {e}")
        return False


def call_vexhelix_api(
    binary_path: Path,
    decompiled_code: str,
    function_name: str,
    vexhelix_url: str,
    language: str = "c",
    num_args: int = 3,
    loop_bound: int = 5
) -> VexHelixResult:
    """Call VexHelix API to verify semantic equivalence."""
    
    lang_str = "cpp" if language.lower() == "cpp" else "c"
    last_error = None
    
    for attempt in range(VEXHELIX_RETRIES):
        try:
            with open(binary_path, 'rb') as binary_file:
                files = {
                    'original_binary': (binary_path.name, binary_file, 'application/octet-stream')
                }
                data = {
                    'decompiled_code': decompiled_code,
                    'function_name': function_name,
                    'language': lang_str,
                    'num_args': str(num_args),
                    'loop_bound': str(loop_bound),
                    'timeout': str(VEXHELIX_TIMEOUT)
                }
                
                response = requests.post(
                    f"{vexhelix_url}/verify",
                    files=files,
                    data=data,
                    timeout=VEXHELIX_TIMEOUT + 30
                )
            
            if response.status_code == 200:
                result = response.json()
                status = result.get('status', 'error')
                
                if status == 'equivalent':
                    print(f"[VexHelix] ✓✓✓ EQUIVALENT - Semantic match!")
                elif status == 'different':
                    div_count = len(result.get('divergences', []))
                    print(f"[VexHelix] ✗ DIFFERENT - Found {div_count} divergence(s)")
                elif status == 'timeout':
                    print(f"[VexHelix] ⏱ TIMEOUT")
                elif status == 'error':
                    print(f"[VexHelix] ⚠ ERROR - {result.get('message', 'Unknown')}")
                
                return VexHelixResult(
                    success=True,
                    status=status,
                    equivalent=result.get('equivalent'),
                    divergences=result.get('divergences'),
                    statistics=result.get('statistics'),
                    error_message=result.get('message') if status == 'error' else None,
                    compilation_error=result.get('compilation_error')
                )
            else:
                last_error = f"HTTP {response.status_code}: {response.text[:500]}"
                if response.status_code >= 500:
                    print(f"[VexHelix] Server error (attempt {attempt + 1}), retrying...")
                    time.sleep(2 ** attempt)
                    continue
                return VexHelixResult(
                    success=False, status='error', equivalent=None, divergences=None,
                    statistics=None, error_message=last_error, compilation_error=None
                )
        
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_error = str(e)[:200]
            if attempt < VEXHELIX_RETRIES - 1:
                print(f"[VexHelix] Connection error (attempt {attempt + 1}), retrying...")
                time.sleep(2 ** attempt)
                continue
        except Exception as e:
            return VexHelixResult(
                success=False, status='error', equivalent=None, divergences=None,
                statistics=None, error_message=str(e)[:200], compilation_error=None
            )
    
    return VexHelixResult(
        success=False, status='error', equivalent=None, divergences=None,
        statistics=None, error_message=f"Failed after {VEXHELIX_RETRIES} retries: {last_error}",
        compilation_error=None
    )


# =============================================================================
# COMPILATION
# =============================================================================

def get_optimization_level(opt_str: str) -> OptimizationLevel:
    """Convert optimization level string to enum."""
    opt_map = {
        "O0": OptimizationLevel.O0,
        "O1": OptimizationLevel.O1,
        "O2": OptimizationLevel.O2,
        "O3": OptimizationLevel.O3,
        "-O0": OptimizationLevel.O0,
        "-O1": OptimizationLevel.O1,
        "-O2": OptimizationLevel.O2,
        "-O3": OptimizationLevel.O3,
    }
    return opt_map.get(opt_str, OptimizationLevel.O0)


def compile_code(
    code: str,
    language: str,
    temp_dir: Path,
    opt: str = "O0"
) -> Tuple[bool, str, Optional[Path]]:
    """Compile code and return (success, message, executable_path)."""
    
    compiler = Compiler()
    file_extension = "cpp" if language == "cpp" else "c"
    source_file = temp_dir / f"code.{file_extension}"
    executable_path = temp_dir / "executable.out"
    
    with open(source_file, "w") as f:
        f.write(code)
    
    opt_level = get_optimization_level(opt)
    status, message = compiler.compile_source(
        source_file_path=source_file,
        output_file_path=executable_path,
        opt=opt_level,
        is_cpp=(language == "cpp"),
        c_flag=True
    )
    
    if status:
        return True, message, executable_path
    else:
        return False, message, None


# =============================================================================
# MAIN PIPELINE
# =============================================================================

def run_pipeline(
    executable_path: Path,
    gemini_provider: str,
    gemini_model_name: str,
    gemini_api_key: str,
    language: str = "c",
    function_name: str = "func0",
    opt: str = "O0",
    output_dir: Optional[Path] = None,
    vexhelix_url: str = DEFAULT_VEXHELIX_URL,
    ghidra_root: Optional[Path] = None,
    num_args: int = 3
) -> DecompilationResult:
    """
    Run the complete VERITAS decompilation pipeline on a single executable.
    
    Args:
        executable_path: Path to the executable binary
        gemini_provider: LLM provider (should be "gemini")
        gemini_model_name: Gemini model name (e.g., "gemini-2.5-pro")
        gemini_api_key: Google API key for Gemini
        language: Target language ("c" or "cpp")
        function_name: Name of the function to decompile
        opt: Optimization level for recompilation
        output_dir: Directory for output files
        vexhelix_url: URL of VexHelix API
        ghidra_root: Path to Ghidra installation
        num_args: Number of function arguments for VexHelix
        
    Returns:
        DecompilationResult with the decompiled code and statistics
    """
    
    print("=" * 70)
    print("VERITAS Demo - Single Executable Decompilation Pipeline")
    print("=" * 70)
    print(f"  Executable: {executable_path}")
    print(f"  Language: {language}")
    print(f"  Function: {function_name}")
    print(f"  Optimization: {opt}")
    print(f"  Model: {gemini_model_name}")
    print("=" * 70)
    
    stats = {
        'static_repair_iterations': 0,
        'semantic_repair_iterations': 0,
        'vexhelix_calls': 0,
        'vexhelix_equivalent_achieved': False,
        'final_result': None,
        'language': language
    }
    
    # Validate executable exists
    if not executable_path.exists():
        return DecompilationResult(
            success=False,
            original_ghidra="",
            optimized_code="",
            gemini_signature=None,
            type_constraints=None,
            stats=stats,
            error_message=f"Executable not found: {executable_path}"
        )
    
    # Setup output directory
    if output_dir is None:
        output_dir = DEMO_DIR / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Get Ghidra root from config if not provided
    if ghidra_root is None:
        ghidra_root = Path(VERITAS_CONFIG.get("paths", {}).get(
            "ghidra_root_path", 
            "/workspace/home/b220032cs/fyp/repos/ansaf/common/ghidra_11.0.3_PUBLIC"
        ))
    
    # Initialize components
    print("\n[1/7] Initializing components...")
    
    try:
        ghidra = Ghidra()
        print("  ✓ Ghidra initialized")
    except Exception as e:
        print(f"  ✗ Ghidra initialization failed: {e}")
        return DecompilationResult(
            success=False, original_ghidra="", optimized_code="",
            gemini_signature=None, type_constraints=None, stats=stats,
            error_message=f"Ghidra initialization failed: {e}"
        )
    
    try:
        llm = GeminiInterface(
            api_key=gemini_api_key,
            model_name=gemini_model_name,
            temperature=0.3
        )
        print(f"  ✓ LLM initialized ({gemini_model_name})")
    except Exception as e:
        print(f"  ✗ LLM initialization failed: {e}")
        return DecompilationResult(
            success=False, original_ghidra="", optimized_code="",
            gemini_signature=None, type_constraints=None, stats=stats,
            error_message=f"LLM initialization failed: {e}"
        )
    
    try:
        type_analyzer = create_type_analyzer(
            provider=gemini_provider,
            api_key=gemini_api_key,
            model_name=gemini_model_name
        )
        print("  ✓ Type analyzer initialized")
    except Exception as e:
        print(f"  ⚠ Type analyzer initialization failed: {e}")
        type_analyzer = None
    
    # Check VexHelix health
    vexhelix_available = check_vexhelix_health(vexhelix_url)
    if vexhelix_available:
        print("  ✓ VexHelix API available")
    else:
        print("  ⚠ VexHelix API unavailable - semantic verification disabled")
    
    # Step 2: Ghidra Analysis
    print("\n[2/7] Running Ghidra analysis...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        ghidra_output_dir = temp_path / "ghidra"
        ghidra_output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            success, ghidra_result = ghidra.convert_executable_to_ghidra(
                str(executable_path), 
                str(ghidra_output_dir)
            )
            
            if not success:
                print(f"  ✗ Ghidra decompilation failed: {ghidra_result}")
                return DecompilationResult(
                    success=False, original_ghidra="", optimized_code="",
                    gemini_signature=None, type_constraints=None, stats=stats,
                    error_message=f"Ghidra decompilation failed: {ghidra_result}"
                )
            
            ghidra_code = ghidra_result
            print(f"  ✓ Ghidra decompilation completed ({len(ghidra_code)} chars)")
            
        except Exception as e:
            print(f"  ✗ Ghidra error: {e}")
            return DecompilationResult(
                success=False, original_ghidra="", optimized_code="",
                gemini_signature=None, type_constraints=None, stats=stats,
                error_message=f"Ghidra error: {e}"
            )
        
        # Extract assembly using objdump
        print("\n[3/7] Extracting assembly...")
        try:
            result = subprocess.run(
                ["objdump", "-d", str(executable_path)],
                capture_output=True,
                text=True,
                timeout=60
            )
            asm = result.stdout if result.returncode == 0 else ""
            print(f"  ✓ Assembly extracted ({len(asm)} chars)")
        except Exception as e:
            print(f"  ⚠ Assembly extraction failed: {e}")
            asm = ""
        
        # Step 4: Type Constraint Generation
        print("\n[4/7] Generating type constraints...")
        
        type_constraints = None
        
        # Try TypeForge first
        typeforge_output = temp_path / "typeforge"
        try:
            type_constraints = acquire_typeforge_constraints(
                executable_path,
                ghidra_root,
                typeforge_output
            )
            if type_constraints:
                print(f"  ✓ TypeForge constraints acquired")
        except Exception as e:
            print(f"  ⚠ TypeForge failed: {e}")
        
        # Fallback to Typehoon
        if not type_constraints:
            try:
                typehoon_result = extract_typehoon_constraints(
                    str(executable_path),
                    function_name
                )
                if typehoon_result.get("success"):
                    type_constraints = typehoon_result
                    print(f"  ✓ Typehoon constraints acquired")
                else:
                    print(f"  ⚠ Typehoon failed: {typehoon_result.get('error')}")
            except Exception as e:
                print(f"  ⚠ Typehoon failed: {e}")
        
        if not type_constraints:
            print("  ⚠ No type constraints available")
        
        # Step 5: Gemini Type Signature Analysis
        print("\n[5/7] Analyzing function signature with Gemini...")
        
        gemini_signature = None
        signature_analysis = ""
        
        if type_analyzer:
            try:
                gemini_signature = type_analyzer.analyze_signature(
                    ghidra_code,
                    asm,
                    type_constraints
                )
                
                if gemini_signature:
                    signature_analysis = format_gemini_signature_for_prompt(gemini_signature)
                    print(f"  ✓ Gemini signature: ret={gemini_signature.get('return_type')}, "
                          f"args={gemini_signature.get('arg_count')}")
                else:
                    print("  ⚠ Gemini signature analysis returned empty")
            except Exception as e:
                print(f"  ⚠ Gemini signature analysis failed: {e}")
        else:
            print("  ⚠ Type analyzer not available")
        
        # Step 6: Generate Summary
        print("\n[6/7] Generating function summary...")
        
        summary_prompt = "Summarize what this function does in one sentence."
        if ghidra_code:
            summary_prompt += f"\n\nGhidra Code:\n```c\n{ghidra_code}\n```"
        if asm:
            summary_prompt += f"\n\nAssembly:\n```asm\n{asm[:2000]}\n```"
        
        try:
            function_summary = llm.generate(summary_prompt)
            print(f"  ✓ Summary: {function_summary[:100]}...")
        except Exception as e:
            print(f"  ⚠ Summary generation failed: {e}")
            function_summary = "Function summary unavailable."
        
        # Step 7: Main Optimization Loop
        print("\n[7/7] Running optimization loop...")
        
        # Generate initial code
        initial_prompt = get_initial_prompt(
            ghidra_code=ghidra_code,
            asm=asm,
            function_summary=function_summary,
            type_constraints=type_constraints,
            signature_analysis=signature_analysis,
            language=language
        )
        
        try:
            optimized_code = llm.generate(initial_prompt)
            if not optimized_code.strip():
                raise RuntimeError("LLM returned empty response")
            print("  ✓ Initial code generated")
        except Exception as e:
            print(f"  ✗ Initial generation failed: {e}")
            return DecompilationResult(
                success=False, original_ghidra=ghidra_code, optimized_code="",
                gemini_signature=gemini_signature, type_constraints=type_constraints, 
                stats=stats, error_message=f"Initial generation failed: {e}"
            )
        
        best_code = optimized_code
        best_divergence_count = float('inf')
        stagnant_count = 0
        error_normalizer = ErrorNormalizer()
        
        # Main repair loop
        for iteration in range(MAX_REPAIR_ITERATIONS):
            print(f"\n  === Iteration {iteration + 1}/{MAX_REPAIR_ITERATIONS} ===")
            
            # Phase 1: Static Repair
            compile_success, compile_message, exe_path = compile_code(
                optimized_code, language, temp_path, opt
            )
            
            if not compile_success:
                print(f"  [Static] Code doesn't compile, fixing...")
                stats['static_repair_iterations'] += 1
                
                error_prompt = error_normalizer.format_for_llm(compile_message)
                repair_prompt = get_static_repair_prompt(
                    code=optimized_code,
                    compilation_errors=error_prompt,
                    function_summary=function_summary,
                    type_constraints=type_constraints,
                    signature_analysis=signature_analysis,
                    language=language,
                    asm=asm
                )
                
                try:
                    new_code = llm.generate(repair_prompt)
                    if new_code.strip():
                        optimized_code = new_code
                    print("  [Static] Received repaired code")
                except Exception as e:
                    print(f"  [Static] LLM error: {e}")
                continue
            
            print("  [Static] ✓ Compiles")
            
            # Skip VexHelix if not available
            if not vexhelix_available:
                print("  [Semantic] VexHelix unavailable, returning compiled code")
                stats['final_result'] = 'compiled_no_verification'
                break
            
            # Phase 2: Semantic Verification
            print("  [Semantic] Calling VexHelix...")
            stats['vexhelix_calls'] += 1
            
            vexhelix_result = call_vexhelix_api(
                binary_path=executable_path,
                decompiled_code=optimized_code,
                function_name=function_name,
                vexhelix_url=vexhelix_url,
                language=language,
                num_args=num_args,
                loop_bound=VEXHELIX_LOOP_BOUND
            )
            
            if not vexhelix_result.success and vexhelix_result.status == 'error':
                if vexhelix_result.compilation_error:
                    print("  [Semantic] VexHelix compile error, fixing...")
                    stats['static_repair_iterations'] += 1
                    
                    repair_prompt = get_static_repair_prompt(
                        code=optimized_code,
                        compilation_errors=vexhelix_result.compilation_error,
                        function_summary=function_summary,
                        type_constraints=type_constraints,
                        signature_analysis=signature_analysis,
                        language=language,
                        asm=asm
                    )
                    
                    try:
                        new_code = llm.generate(repair_prompt)
                        if new_code.strip():
                            optimized_code = new_code
                    except Exception as e:
                        print(f"  [Semantic] LLM error: {e}")
                    continue
                
                print(f"  [Semantic] VexHelix API error: {vexhelix_result.error_message}")
                stats['final_result'] = 'vexhelix_error'
                break
            
            if vexhelix_result.status == 'timeout':
                print("  [Semantic] VexHelix timeout")
                stats['final_result'] = 'vexhelix_timeout'
                break
            
            if vexhelix_result.status == 'equivalent' or vexhelix_result.equivalent:
                print("  ✓✓✓ EQUIVALENT!")
                stats['vexhelix_equivalent_achieved'] = True
                stats['final_result'] = 'equivalent'
                break
            
            # Phase 3: Check for stagnation
            current_divergences = len(vexhelix_result.divergences or [])
            print(f"  [Semantic] ✗ DIFFERENT - {current_divergences} divergences")
            
            if current_divergences < best_divergence_count:
                best_divergence_count = current_divergences
                best_code = optimized_code
                stagnant_count = 0
                print(f"  [Semantic] Improvement! Best: {best_divergence_count}")
            else:
                stagnant_count += 1
                print(f"  [Semantic] No improvement ({stagnant_count}/{MAX_STAGNANT_ITERATIONS})")
                
                if stagnant_count >= MAX_STAGNANT_ITERATIONS:
                    print("  [Semantic] Stagnation detected, returning best code")
                    stats['final_result'] = 'stagnant_divergences'
                    optimized_code = best_code
                    break
            
            # Phase 4: Semantic Repair
            print("  [Semantic] Attempting semantic repair...")
            stats['semantic_repair_iterations'] += 1
            
            semantic_prompt = get_semantic_repair_prompt(
                original_asm=asm,
                original_ghidra=ghidra_code,
                current_code=optimized_code,
                function_summary=function_summary,
                vexhelix_result=vexhelix_result,
                type_constraints=type_constraints,
                signature_analysis=signature_analysis,
                language=language
            )
            
            try:
                new_code = llm.generate(semantic_prompt)
                if new_code and new_code.strip():
                    optimized_code = new_code
                print("  [Semantic] Received repaired code")
            except Exception as e:
                print(f"  [Semantic] LLM error: {e}")
        
        else:
            # Max iterations reached
            print(f"\n  Max iterations ({MAX_REPAIR_ITERATIONS}) reached")
            stats['final_result'] = 'max_iterations'
            optimized_code = best_code
        
        # Save output
        output_file = output_dir / f"{executable_path.stem}_decompiled.{language}"
        with open(output_file, "w") as f:
            f.write(optimized_code)
        print(f"\n✓ Output saved to: {output_file}")
        
        # Save stats
        stats_file = output_dir / f"{executable_path.stem}_stats.json"
        with open(stats_file, "w") as f:
            json.dump({
                "stats": stats,
                "gemini_signature": gemini_signature,
                "has_type_constraints": type_constraints is not None
            }, f, indent=2)
        print(f"✓ Stats saved to: {stats_file}")
        
        return DecompilationResult(
            success=stats.get('final_result') == 'equivalent',
            original_ghidra=ghidra_code,
            optimized_code=optimized_code,
            gemini_signature=gemini_signature,
            type_constraints=type_constraints,
            stats=stats
        )


# =============================================================================
# CLI INTERFACE
# =============================================================================

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="VERITAS Demo - Single Executable Decompilation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python veritas.py --executable /path/to/binary --gemini_api_key YOUR_KEY

    python veritas.py --executable /path/to/binary \\
                      --gemini_provider gemini \\
                      --gemini_model_name gemini-2.5-pro \\
                      --gemini_api_key YOUR_KEY \\
                      --language cpp \\
                      --function_name func0 \\
                      --opt O2
        """
    )
    
    # Required arguments
    parser.add_argument(
        "--executable",
        type=str,
        required=True,
        help="Path to the executable binary to decompile"
    )
    
    parser.add_argument(
        "--gemini_api_key",
        type=str,
        required=True,
        help="Google API key for Gemini"
    )
    
    # Optional arguments
    parser.add_argument(
        "--gemini_provider",
        type=str,
        default="gemini",
        help="LLM provider (default: gemini)"
    )
    
    parser.add_argument(
        "--gemini_model_name",
        type=str,
        default="gemini-2.5-pro",
        help="Gemini model name (default: gemini-2.5-pro)"
    )
    
    parser.add_argument(
        "--language",
        type=str,
        default="c",
        choices=["c", "cpp"],
        help="Target language (default: c)"
    )
    
    parser.add_argument(
        "--function_name",
        type=str,
        default="func0",
        help="Name of the function to decompile (default: func0)"
    )
    
    parser.add_argument(
        "--opt",
        type=str,
        default="O0",
        choices=["O0", "O1", "O2", "O3"],
        help="Optimization level for recompilation (default: O0)"
    )
    
    parser.add_argument(
        "--output_dir",
        type=str,
        default=None,
        help="Directory for output files (default: demo/output)"
    )
    
    parser.add_argument(
        "--vexhelix_url",
        type=str,
        default=DEFAULT_VEXHELIX_URL,
        help=f"VexHelix API URL (default: {DEFAULT_VEXHELIX_URL})"
    )
    
    parser.add_argument(
        "--ghidra_root",
        type=str,
        default=None,
        help="Path to Ghidra installation"
    )
    
    parser.add_argument(
        "--num_args",
        type=int,
        default=3,
        help="Number of function arguments for VexHelix (default: 3)"
    )
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()
    
    # Validate executable path
    executable_path = Path(args.executable).resolve()
    if not executable_path.exists():
        print(f"Error: Executable not found: {executable_path}")
        sys.exit(1)
    
    # Setup output directory
    output_dir = Path(args.output_dir) if args.output_dir else None
    
    # Setup Ghidra root
    ghidra_root = Path(args.ghidra_root) if args.ghidra_root else None
    
    # Run the pipeline
    result = run_pipeline(
        executable_path=executable_path,
        gemini_provider=args.gemini_provider,
        gemini_model_name=args.gemini_model_name,
        gemini_api_key=args.gemini_api_key,
        language=args.language,
        function_name=args.function_name,
        opt=args.opt,
        output_dir=output_dir,
        vexhelix_url=args.vexhelix_url,
        ghidra_root=ghidra_root,
        num_args=args.num_args
    )
    
    # Print final summary
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"  Success: {result.success}")
    print(f"  Final Result: {result.stats.get('final_result', 'unknown')}")
    print(f"  Static Repair Iterations: {result.stats.get('static_repair_iterations', 0)}")
    print(f"  Semantic Repair Iterations: {result.stats.get('semantic_repair_iterations', 0)}")
    print(f"  VexHelix Calls: {result.stats.get('vexhelix_calls', 0)}")
    print(f"  Equivalent Achieved: {result.stats.get('vexhelix_equivalent_achieved', False)}")
    
    if result.gemini_signature:
        print(f"  Gemini Signature:")
        print(f"    Return Type: {result.gemini_signature.get('return_type')}")
        print(f"    Arg Count: {result.gemini_signature.get('arg_count')}")
        print(f"    Arg Types: {result.gemini_signature.get('arg_types')}")
    
    print("=" * 70)
    
    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
