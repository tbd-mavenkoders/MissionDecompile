"""
Batched HumanEval Collector V7 - TypeForge + VexHelix Integration

This module extends MissionDecompile V6 with:
- TYPE CONSTRAINTS from TypeForge (addresses VexHelix's type inference limitations)
- Static repair (ensure compilation)
- Semantic verification via VexHelix API (ensure logical correctness)
- Semantic repair loop with type-aware prompts
- FULL C and C++ support
- TRUE PIPELINED parallel execution (like CPU pipeline)

Key changes from V6:
- Integrates TypeForge type constraints in ALL prompts (initial, static, semantic)
- Enhanced semantic_repair prompt accounts for type errors not just logic errors
- Type constraints help LLM infer correct:
  * Return types (float vs void, int vs long)
  * Parameter types (int* vs float*, size_t vs int)
  * Local variable types (pointer vs array, signed vs unsigned)
- Better synergy: VexHelix catches semantic bugs, TypeForge guides type fixes
- TRUE CPU-STYLE PIPELINE: compile → ghidra → summary → vexhelix (concurrent stages)
- GLOBAL RATE LIMITER: prevents overwhelming the LLM server
- C++ DEMANGLING: cxxfilt support for finding mangled function names

Pipeline Architecture:
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  COMPILE    │──►│   GHIDRA    │──►│  SUMMARIES  │──►│  VEXHELIX   │
│  width=20   │   │  width=12   │   │  width=12   │   │  width=12   │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
     ↑                  ↑                 ↑                  ↑
 compile_q          ghidra_q          summary_q          vexhelix_q
"""

import yaml
from pathlib import Path
import shutil
import tempfile
import os
import sys
from typing import Tuple, List, Dict, Optional
import json
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import subprocess
import time
from dataclasses import dataclass, field
import requests
import threading
from queue import Queue

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.llm_interface import (
    create_llm_interface, 
    LLMInterface, 
    GLOBAL_RATE_LIMITER,
    set_global_rate_limit,
    get_rate_limiter_stats
)
from utils.compile import Compiler, OptimizationLevel
from utils.ghidra import Ghidra
from utils.clean_errors import ErrorNormalizer
from src.sort_callgraph import build_call_graph, topological_sort
from utils.typehoon_poc import extract_typehoon_constraints, format_typehoon_for_prompt

# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

# Initialize tools
c = Compiler()
g = Ghidra()

llm_interface = create_llm_interface(
    provider=config["llm"]["vllm_provider"],
    model_name=config["llm"]["vllm_model_name"],
    base_url=config["llm"]["vllm_base_url"]
)

corpus_path = Path(config["humaneval"]["corpus_path"])
output_dir = Path(config["humaneval"]["output_path"])

# Thread-safe progress tracking
print_lock = threading.Lock()
active_count = 0
completed_count = 0
total_tasks = 0

# =============================================================================
# CONFIGURATION
# =============================================================================

# PIPELINE STAGE WIDTHS (like CPU pipeline - each stage has its own parallelism)
# Items flow through: COMPILE → GHIDRA → SUMMARY → VEXHELIX
# IMPORTANT: LLM can only handle 24 concurrent requests total!
PIPELINE_COMPILE_WIDTH = 20   # Compile is fast (gcc subprocess)
PIPELINE_GHIDRA_WIDTH = 12    # Ghidra is memory-heavy, limit parallelism
PIPELINE_SUMMARY_WIDTH = 12   # LLM bound: 12 concurrent summary requests
PIPELINE_VEXHELIX_WIDTH = 12  # LLM bound: 12 concurrent repair loops (each uses LLM)

# Legacy batching configuration
COMPILATION_BATCH_SIZE = 20
GHIDRA_BATCH_SIZE = 8
LLM_BATCH_SIZE = 12

# Concurrent static repair configuration
CONCURRENT_REPAIR_SIZE = 12

# VexHelix API configuration
VEXHELIX_API_URL = "http://127.0.0.1:8001"
VEXHELIX_TIMEOUT = 180
VEXHELIX_LOOP_BOUND = 5
VEXHELIX_RETRIES = 3

# Repair configuration
MAX_REPAIR_ITERATIONS = 5
MAX_STATIC_REPAIR_PER_CYCLE = 3
MAX_STAGNANT_ITERATIONS = 3
PARALLEL_REPAIR_WORKERS = 12

# History tracking for semantic repair (avoid repeating mistakes)
MAX_CODE_HISTORY = 2  # Keep last N best attempts in prompt

# Token limit configuration (GPT-OSS-20B has 130K context)
MAX_CONTEXT_TOKENS = 130_000
MAX_ERROR_CHARS = 2000
MAX_ASM_CHARS = 8000
MAX_CODE_CHARS = 12000
MAX_TYPE_CONSTRAINT_CHARS = 3000  # NEW: Limit for type constraints


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
class CompilationResult:
    """Result of compiling a single program."""
    index: int
    success: bool
    executable_path: Optional[Path]
    error_message: Optional[str]
    data: Dict


@dataclass
class RepairTask:
    """A single repair task to be processed concurrently."""
    index: int
    prog_data: Dict
    func_data: Dict
    temp_dir: Path
    iteration: int = 0


@dataclass
class RepairResult:
    """Result from a repair task."""
    index: int
    success: bool
    optimized_code: str
    compile_success: bool
    needs_semantic_check: bool
    stats: Dict = field(default_factory=dict)
    error_message: Optional[str] = None


# =============================================================================
# GLOBAL TRACKING FOR TYPEHOON USAGE (fallback when TypeForge unavailable)
# =============================================================================
_typehoon_stats = {
    'called': 0,       # Times Typehoon was called (TypeForge unavailable)
    'success': 0,      # Successful Typehoon extractions
    'failed': 0,       # Failed Typehoon extractions
    'failed_indices': []  # List of indices where Typehoon failed
}

def get_typehoon_stats() -> Dict:
    """Return Typehoon usage statistics."""
    return _typehoon_stats.copy()

def reset_typehoon_stats():
    """Reset Typehoon statistics."""
    global _typehoon_stats
    _typehoon_stats = {
        'called': 0,
        'success': 0,
        'failed': 0,
        'failed_indices': []
    }


# =============================================================================
# TYPEFORGE TYPE CONSTRAINT EXTRACTION (from v4/old_v7)
# WITH TYPEHOON FALLBACK (V7 enhancement)
# =============================================================================

def get_type_constraints(data: Dict, binary_path: Optional[str] = None) -> Dict:
    """
    Enrich the type constraints using TypeForge, with Typehoon as fallback.
    
    TypeForge provides (PRIMARY - more detailed):
    - Parameter types and names
    - Local variable types
    - Struct layouts with field offsets
    - Pointer vs array disambiguation
    - Signed vs unsigned integer types
    
    Typehoon provides (FALLBACK - when TypeForge unavailable):
    - Return type inference
    - Parameter type inference
    - Local variable type inference
    - Available for ANY binary via angr
    
    This information is CRITICAL because VexHelix cannot verify type correctness,
    only semantic equivalence. If the LLM uses wrong types, VexHelix may still
    report "equivalent" but the code is incorrect.
    
    Args:
        data: Dict - The program data dictionary containing 'index'
        binary_path: Optional path to the compiled binary for Typehoon fallback
    
    Returns:
        Dict with type constraints or empty dict if not available
    """
    index = data.get('index')
    if index is None:
        return {}
    
    typeforge_path = corpus_path / "typeforge" / f"func_{index}"
    
    # Try TypeForge first (more detailed)
    typeforge_constraints = _load_typeforge_constraints(typeforge_path, index)
    
    if typeforge_constraints:
        return typeforge_constraints
    
    # Fallback to Typehoon if TypeForge unavailable and binary path provided
    if binary_path and Path(binary_path).exists():
        print(f"[Typehoon] TypeForge unavailable for func_{index}, trying Typehoon...")
        typehoon_constraints = _load_typehoon_constraints(binary_path, index)
        if typehoon_constraints:
            return typehoon_constraints
    
    return {}


def _load_typeforge_constraints(typeforge_path: Path, index: int) -> Dict:
    """Load TypeForge constraints from the corpus."""
    # If TypeForge data doesn't exist, return empty
    if not typeforge_path.exists():
        return {}
    
    # Check if there are constraint files (more than just varType.json)
    type_files = list(typeforge_path.glob("*.json"))
    if len(type_files) <= 1:
        return {}
    
    # Read the main varType.json file
    varType_file = typeforge_path / "varType.json"
    all_constraints = []
    
    if varType_file.exists():
        try:
            with open(varType_file, "r") as f:
                varType = json.load(f)
            
            # Select only constraints pertaining to func0
            for type_constraint in varType.values():
                if type_constraint.get('Name') != 'func0':
                    continue
                
                # Process local variables
                local_variables = type_constraint.get('LocalVariables', {})
                for var_loc, var_info in local_variables.items():
                    if 'TypeConstraint' in var_info:
                        file_name = var_info['TypeConstraint']
                        # Try both _final.json and _final_DI.json variants
                        constraint_file = typeforge_path / f"{file_name}_final.json"
                        constraint_file_dl = typeforge_path / f"{file_name}_final_DI.json"
                        
                        if constraint_file.exists():
                            with open(constraint_file, "r") as cf:
                                constraint_data = json.load(cf)
                            var_info['TypeConstraint'] = constraint_data
                        elif constraint_file_dl.exists():
                            with open(constraint_file_dl, "r") as cf:
                                constraint_data = json.load(cf)
                            var_info['TypeConstraint'] = constraint_data
                
                # Process parameters
                parameters = type_constraint.get('Parameters', {})
                for param_loc, param_info in parameters.items():
                    if 'TypeConstraint' in param_info:
                        file_name = param_info['TypeConstraint']
                        constraint_file = typeforge_path / f"{file_name}.json"
                        if constraint_file.exists():
                            with open(constraint_file, "r") as cf:
                                constraint_data = json.load(cf)
                            param_info['TypeConstraint'] = constraint_data
                
                all_constraints.append(type_constraint)
        except Exception as e:
            print(f"[TypeForge] Error loading constraints for func_{index}: {e}")
            return {}
    
    return all_constraints if all_constraints else {}


def _load_typehoon_constraints(binary_path: str, index: int) -> Dict:
    """
    Load type constraints using angr's Typehoon.
    
    This is the fallback when TypeForge data is unavailable.
    Tracks success/failure statistics for monitoring.
    """
    global _typehoon_stats
    _typehoon_stats['called'] += 1
    
    try:
        # Extract constraints using Typehoon
        constraints = extract_typehoon_constraints(binary_path, "func0")
        
        if constraints.get("success"):
            # Convert Typehoon format to a format similar to TypeForge for consistency
            typehoon_result = {
                "source": "typehoon",
                "function_name": "func0",
                "return_type": constraints.get("return_type"),
                "parameters": constraints.get("parameters", []),
                "local_variables": constraints.get("local_variables", []),
                "raw_constraints": constraints.get("constraints", [])
            }
            _typehoon_stats['success'] += 1
            print(f"[Typehoon] Successfully extracted types for func_{index}")
            return [typehoon_result]  # Return as list for consistency with TypeForge
        else:
            _typehoon_stats['failed'] += 1
            _typehoon_stats['failed_indices'].append(index)
            print(f"[Typehoon] Extraction failed for func_{index}: {constraints.get('error', 'unknown')}")
            return {}
    except Exception as e:
        _typehoon_stats['failed'] += 1
        _typehoon_stats['failed_indices'].append(index)
        print(f"[Typehoon] Error extracting types for func_{index}: {e}")
        return {}


def format_type_constraints_for_prompt(type_constraints: Dict, max_chars: int = MAX_TYPE_CONSTRAINT_CHARS) -> str:
    """
    Format TypeForge or Typehoon constraints into a readable string for LLM prompts.
    
    Args:
        type_constraints: Dict from get_type_constraints()
        max_chars: Maximum characters to include
    
    Returns:
        Formatted string describing the type constraints
    """
    if not type_constraints:
        return ""
    
    lines = []
    
    # Check if this is Typehoon data (has 'source': 'typehoon')
    if isinstance(type_constraints, list) and len(type_constraints) > 0:
        first_constraint = type_constraints[0]
        if first_constraint.get('source') == 'typehoon':
            # Format Typehoon constraints
            lines.append("TYPE CONSTRAINTS (from Typehoon analysis):")
            lines.append("These types were inferred from binary analysis and should guide your implementation:")
            
            for constraint in type_constraints:
                func_name = constraint.get('function_name', 'func0')
                lines.append(f"\nFunction: {func_name}")
                
                # Return type - with warning if void
                ret_type = constraint.get('return_type')
                if ret_type:
                    ret_type_str = ret_type.get('type', 'unknown')
                    lines.append(f"  Return Type: {ret_type_str}")
                    
                    # Add critical warning if return type is void
                    if ret_type_str and ret_type_str.lower() == 'void':
                        lines.append("  ⚠️ WARNING: TypeHoon says 'void' but this MAY BE WRONG!")
                        lines.append("  ⚠️ CHECK ASSEMBLY: If xmm0/eax has value before RET → NOT void!")
                        lines.append("  ⚠️ CHECK SEMANTICS: If function COMPUTES a value → it MUST return it!")
                
                # Parameters
                params = constraint.get('parameters', [])
                if params:
                    lines.append("  Parameters:")
                    for param in params:
                        name = param.get('name', 'unknown')
                        param_type = param.get('type', 'unknown')
                        lines.append(f"    - {name}: {param_type}")
                
                # Local variables
                local_vars = constraint.get('local_variables', [])
                if local_vars:
                    lines.append("  Local Variables:")
                    for i, var in enumerate(local_vars[:15]):  # Limit to 15
                        name = var.get('variable_name', 'unknown')
                        var_type = var.get('variable_type', 'unknown')
                        lines.append(f"    - {name}: {var_type}")
                    if len(local_vars) > 15:
                        lines.append(f"    ... ({len(local_vars) - 15} more)")
            
            result = "\n".join(lines)
            if len(result) > max_chars:
                result = result[:max_chars] + "\n... (type constraints truncated)"
            return result
    
    # Format TypeForge constraints (original format)
    lines.append("TYPE CONSTRAINTS (from TypeForge analysis):")
    lines.append("These types were inferred from binary analysis and should guide your implementation:")
    
    for constraint in type_constraints:
        func_name = constraint.get('Name', 'unknown')
        lines.append(f"\nFunction: {func_name}")
        
        # Parameters
        params = constraint.get('Parameters', {})
        if params:
            lines.append("  Parameters:")
            for param_loc, param_info in params.items():
                name = param_info.get('Name', 'unknown')
                desc = param_info.get('desc', '')
                type_detail = param_info.get('TypeConstraint', {})
                if isinstance(type_detail, dict):
                    type_str = type_detail.get('type', desc)
                else:
                    type_str = desc
                lines.append(f"    - {name}: {type_str}")
        
        # Local variables (limit to most important)
        local_vars = constraint.get('LocalVariables', {})
        if local_vars:
            lines.append("  Local Variables:")
            count = 0
            for var_loc, var_info in local_vars.items():
                if count >= 15:  # Limit to 15 variables
                    lines.append(f"    ... ({len(local_vars) - 15} more)")
                    break
                name = var_info.get('Name', 'unknown')
                desc = var_info.get('desc', '')
                type_detail = var_info.get('TypeConstraint', {})
                if isinstance(type_detail, dict):
                    type_str = type_detail.get('type', desc)
                else:
                    type_str = desc
                lines.append(f"    - {name}: {type_str}")
                count += 1
    
    result = "\n".join(lines)
    
    # Truncate if too long
    if len(result) > max_chars:
        result = result[:max_chars] + "\n... (type constraints truncated)"
    
    return result


# =============================================================================
# VEXHELIX API INTEGRATION
# =============================================================================

def check_vexhelix_health() -> bool:
    """Check if VexHelix API is available and healthy."""
    try:
        response = requests.get(f"{VEXHELIX_API_URL}/health", timeout=10)
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
    language: str = "c",
    num_args: int = 3,
    loop_bound: int = 5
) -> VexHelixResult:
    """
    Call VexHelix API to verify semantic equivalence between binary and decompiled code.
    
    IMPROVED in v7: Retry logic with exponential backoff for transient failures.
    """
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
                    'loop_bound': str(VEXHELIX_LOOP_BOUND),
                    'timeout': str(VEXHELIX_TIMEOUT)
                }
                
                response = requests.post(
                    f"{VEXHELIX_API_URL}/verify",
                    files=files,
                    data=data,
                    timeout=VEXHELIX_TIMEOUT + 30
                )
            
            if response.status_code == 200:
                result = response.json()
                status = result.get('status', 'error')
                equivalent = result.get('equivalent', None)
                
                if status == 'equivalent':
                    print(f"[VexHelix] ✓✓✓ EQUIVALENT - Semantic match!")
                elif status == 'different':
                    div_count = len(result.get('divergences', []))
                    print(f"[VexHelix] ✗ DIFFERENT - Found {div_count} divergence(s)")
                elif status == 'timeout':
                    print(f"[VexHelix] ⏱ TIMEOUT - Execution exceeded time limit")
                elif status == 'error':
                    print(f"[VexHelix] ⚠ ERROR - {result.get('message', 'Unknown error')}")
                
                return VexHelixResult(
                    success=True,
                    status=status,
                    equivalent=equivalent,
                    divergences=result.get('divergences'),
                    statistics=result.get('statistics'),
                    error_message=result.get('message') if status == 'error' else None,
                    compilation_error=result.get('compilation_error')
                )
            else:
                last_error = f"HTTP {response.status_code}: {response.text[:500]}"
                if response.status_code >= 500:
                    print(f"[VexHelix] Server error (attempt {attempt + 1}/{VEXHELIX_RETRIES}), retrying...")
                    time.sleep(2 ** attempt)
                    continue
                return VexHelixResult(
                    success=False, status='error', equivalent=None, divergences=None,
                    statistics=None, error_message=last_error, compilation_error=None
                )
        
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_error = str(e)[:200]
            if attempt < VEXHELIX_RETRIES - 1:
                print(f"[VexHelix] Connection error (attempt {attempt + 1}/{VEXHELIX_RETRIES}), retrying...")
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
# PROMPT GENERATION (V7.1: ALL PROMPTS INCLUDE TYPE CONSTRAINTS + GHIDRA WARNINGS)
# =============================================================================

def get_initial_prompt(
    c_code: str, 
    function_summary: str, 
    caller_and_callee_summary: str, 
    function_sog: str, 
    type_constraints: Dict,
    language: str, 
    asm: str = "",
    signature_analysis: str = ""  # V7.2: LLM-as-judge signature analysis
) -> str:
    """
    Generate the initial prompt for the repair tool.
    
    V7.1 IMPROVEMENT: Enhanced Ghidra warnings with "ALTHOUGH UNLIKELY, STILL PLAUSIBLE" framing.
    V7.2 IMPROVEMENT: Includes LLM-as-judge signature analysis for better type inference.
    """
    initial_prompt = config["prompts"]["system_prompt"]
    
    # Truncate assembly but keep enough for context
    truncated_asm = asm[:5000] if asm else ""
    if asm and len(asm) > 5000:
        truncated_asm += "\n; ... (truncated)"
    
    prompt = f"""{initial_prompt}

═══════════════════════════════════════════════════════════════════════════════
⚠️ CRITICAL: Ghidra pseudocode is NOT ground truth - it may have ERRORS!
═══════════════════════════════════════════════════════════════════════════════

The ASSEMBLY below shows the TRUE behavior. Ghidra's output may be wrong in:

ALTHOUGH UNLIKELY, STILL PLAUSIBLE - Ghidra common errors:
• Wrong return type: void instead of int/float/double (check xmm0/eax before ret)
• Missing float ops: addss/mulss/divss instructions ignored → code appears integer-only
• Empty loop bodies: operations inside loops omitted entirely
• Wrong param types: int instead of float*, long instead of size_t
• Wrong param count: parameters missing or extra ones added
• Artificial temporaries: compiler artifacts kept as real variables
• Control flow errors: structured loops/ifs incorrectly recovered

═══════════════════════════════════════════════════════════════════════════════
🚨 RETURN TYPE INFERENCE - CRITICAL (GHIDRA OFTEN SAYS void INCORRECTLY) 🚨
═══════════════════════════════════════════════════════════════════════════════

CHECK ASSEMBLY BEFORE RET:
• xmm0 set before ret → return type is FLOAT/DOUBLE, NOT void!
• eax/rax set before ret → return type is INT/LONG, NOT void!
• DIVSS xmm0 before ret → definitely returns float!

USE SEMANTIC REASONING:
• If function COMPUTES a value (sum, average, etc.) → it MUST return it!
• If function has loops that accumulate → it returns the result!
• If Ghidra says "void" but function clearly computes → IGNORE Ghidra, return the value!

COMMON: Mean Absolute Deviation pattern (2 loops, 2 divss) → returns FLOAT!

═══════════════════════════════════════════════════════════════════════════════
🚨 C++ STL WARNING (Ghidra POORLY handles std::vector/string) 🚨
═══════════════════════════════════════════════════════════════════════════════

For std::vector<float>:
• Ghidra may say "void func(vector)" → actually "float func(vector<float>)"
• Ghidra may show std::abs() called but result DISCARDED → WRONG, accumulate it!
• If assembly has addss/divss loops → function returns float!

ASSEMBLY INSTRUCTION HINTS:
• movss/addss/mulss/divss → floating-point operations REQUIRED
• cvtsi2ss → int to float conversion
• xmm0 set before ret → return type is float/double
• eax/rax set before ret → return type is int/long
• ANDPS with 0x7fffffff → fabsf() absolute value operation

═══════════════════════════════════════════════════════════════════════════════
ASSEMBLY (GROUND TRUTH - this is what the binary ACTUALLY does):
═══════════════════════════════════════════════════════════════════════════════
```asm
{truncated_asm}
```

═══════════════════════════════════════════════════════════════════════════════
GHIDRA PSEUDOCODE (MAY BE INCORRECT - use as rough guide only):
═══════════════════════════════════════════════════════════════════════════════
```{language}
{c_code}
```

Function Summary: {function_summary}
"""
    
    # V7.2: Add LLM-as-judge signature analysis if available
    if signature_analysis:
        prompt += f"""
═══════════════════════════════════════════════════════════════════════════════
🔍 SIGNATURE ANALYSIS (LLM-as-judge - identified Ghidra errors):
═══════════════════════════════════════════════════════════════════════════════
{signature_analysis[:1500]}

⚠️ USE THIS ANALYSIS! If it says Ghidra's return type is WRONG, fix it!
"""
    
    # V7: Add type constraints if available
    type_str = format_type_constraints_for_prompt(type_constraints)
    if type_str:
        prompt += f"\n\n{type_str}"
    
    if caller_and_callee_summary:
        prompt += f"\n\nCaller and Callee Summary:\n{caller_and_callee_summary}"
    if function_sog:
        prompt += f"\n\nFunction SOG:\n{function_sog}"
    
    return prompt


def get_static_repair_prompt(
    c_code: str, 
    compilation_errors: str, 
    function_summary: str,
    caller_and_callee_summary: str, 
    function_sog: str, 
    type_constraints: Dict,
    language: str
) -> str:
    """
    Generate the static repair prompt for compilation errors.
    
    V7 IMPROVEMENT: Includes type constraints to help fix type-related errors.
    Many compilation errors are due to type mismatches that TypeForge can help resolve.
    """
    repair_prompt = config["prompts"]["compilation_error"]
    lang_label = "cpp" if language == "cpp" else "c"
    
    # Truncate errors and code
    truncated_errors = compilation_errors[:MAX_ERROR_CHARS]
    if len(compilation_errors) > MAX_ERROR_CHARS:
        truncated_errors += "\n... (error truncated)"
    truncated_code = c_code[:MAX_CODE_CHARS]
    if len(c_code) > MAX_CODE_CHARS:
        truncated_code += "\n// ... (code truncated)"
    
    prompt = f"{repair_prompt}\n\n```{lang_label}\nLanguage:{language}\nSummary:{function_summary}\nCode:{truncated_code}\n```\n\nCompilation Errors:\n{truncated_errors}\n\nPlease provide the corrected {language.upper()} code."
    
    # V7: Add type constraints to help fix type errors
    type_str = format_type_constraints_for_prompt(type_constraints)
    if type_str:
        prompt += f"\n\n{type_str}\n\nUse these type constraints to help fix any type-related compilation errors."
    
    if caller_and_callee_summary:
        prompt += f"\n\nCaller and Callee Summary:\n{caller_and_callee_summary}"
    if function_sog:
        prompt += f"\n\nFunction SOG:\n{function_sog}"
    
    return prompt


def get_semantic_repair_prompt(
    original_asm: str,
    original_ghidra: str,
    current_code: str,
    function_summary: str,
    vexhelix_result: VexHelixResult,
    type_constraints: Dict,
    language: str,
    code_history: List[Tuple[str, int]] = None,  # V7.1: Previous attempts to avoid repeating mistakes
    signature_analysis: str = ""  # V7.2: LLM-as-judge signature analysis
) -> str:
    """
    Generate robust semantic repair prompt - assembly is ground truth, Ghidra is unreliable.
    
    V7.1 ENHANCEMENT:
    - Includes history of previous failed attempts to avoid repeating mistakes
    - Improved Ghidra warning: "ALTHOUGH UNLIKELY, STILL PLAUSIBLE" framing
    - More comprehensive list of Ghidra failure modes
    - TypeForge type constraints for type errors VexHelix cannot detect
    
    V7.2 ENHANCEMENT:
    - Includes LLM-as-judge signature analysis to identify Ghidra errors early
    """
    # Truncate assembly but keep more of it (it's the ground truth!)
    truncated_asm = original_asm[:MAX_ASM_CHARS] if original_asm else ""
    if original_asm and len(original_asm) > MAX_ASM_CHARS:
        truncated_asm += "\n; ... (assembly truncated)"
    
    # Truncate Ghidra code
    truncated_ghidra = original_ghidra[:MAX_CODE_CHARS] if original_ghidra else ""
    if original_ghidra and len(original_ghidra) > MAX_CODE_CHARS:
        truncated_ghidra += "\n// ... (Ghidra code truncated)"
    
    # Truncate current code
    truncated_current = current_code[:MAX_CODE_CHARS] if current_code else ""
    if current_code and len(current_code) > MAX_CODE_CHARS:
        truncated_current += "\n// ... (current code truncated)"
    
    prompt = f"""You are fixing decompiled code that produces WRONG outputs. The symbolic verifier found semantic differences.

═══════════════════════════════════════════════════════════════════════════════
CRITICAL: ASSEMBLY IS GROUND TRUTH - Ghidra pseudocode is NOT reliable!
═══════════════════════════════════════════════════════════════════════════════

Ghidra's decompiler output may be WRONG in any of these ways (although each seems unlikely, they are PLAUSIBLE and COMMON):

SIGNATURE ERRORS (ALTHOUGH UNLIKELY, STILL PLAUSIBLE):
• Wrong return type: void instead of int/float/double (check xmm0/eax before ret)
• Wrong parameter count: missing params or extra params
• Wrong parameter types: int vs float*, long vs size_t, signed vs unsigned
• Swapped parameters: argument order doesn't match actual use

TYPE ERRORS (ALTHOUGH UNLIKELY, STILL PLAUSIBLE):
• Pointer vs integer confusion: treating addresses as values
• Signed vs unsigned: wrong signedness affects comparisons
• Float vs int: missing floating-point ops (look for addss/mulss/divss)
• Array vs pointer: wrong indexing or stride

CONTROL FLOW ERRORS (ALTHOUGH UNLIKELY, STILL PLAUSIBLE):
• Empty loop bodies: actual operations omitted
• Wrong loop bounds: off-by-one, wrong direction
• Missing branches: conditional code collapsed
• Goto artifacts: structured control obscured

DATA FLOW ERRORS (ALTHOUGH UNLIKELY, STILL PLAUSIBLE):
• Artificial temporaries: merged or split incorrectly  
• Wrong variable identity: different vars confused
• Missing operations: arithmetic silently dropped
• Compiler artifacts: ABI/optimization noise kept

═══════════════════════════════════════════════════════════════════════════════
🚨 RETURN TYPE INFERENCE - THE #1 CAUSE OF SEMANTIC FAILURES 🚨
═══════════════════════════════════════════════════════════════════════════════

CHECK ASSEMBLY BEFORE RET INSTRUCTION:
• If xmm0 has a value before RET → return type is FLOAT or DOUBLE, NOT void!
• If eax/rax has a value before RET → return type is INT/LONG, NOT void!
• If DIVSS xmm0 / DIVSD xmm0 before RET → definitely returns float/double!
• PXOR xmm0,xmm0 + CVTSI2SS + DIVSS pattern → returns FLOAT!

USE SEMANTIC REASONING (when assembly is unclear):
• If function COMPUTES something (sum, average, count, etc.) → it MUST return it!
• If function has accumulator loops → it MUST return the accumulated value!
• If Ghidra shows computations but "return;" with no value → GHIDRA IS WRONG!
• A function that computes but doesn't return makes NO SENSE → add return!

COMMON PATTERN - Mean Absolute Deviation (MAD):
• Loop 1: sum all elements, divide by count → mean
• Loop 2: sum |element - mean| for all elements, divide by count → MAD
• This function MUST return float, even if Ghidra says void!

═══════════════════════════════════════════════════════════════════════════════
🚨 FLOATING-POINT DETECTION - NEVER USE INT FOR FLOAT ASSEMBLY 🚨
═══════════════════════════════════════════════════════════════════════════════

If assembly contains ADDSS, SUBSS, MULSS, DIVSS, MOVSS → use FLOAT types!
If assembly contains ADDSD, SUBSD, MULSD, DIVSD, MOVSD → use DOUBLE types!
If assembly contains ANDPS with 0x7fffffff mask → this is fabsf() absolute value!
If assembly contains CVTSI2SS → converting int to float!

NEVER generate pointer arithmetic (base + count*4) when assembly shows float operations!
NEVER confuse array stride calculation with the actual computation!

═══════════════════════════════════════════════════════════════════════════════
C++ STL RECOVERY (Ghidra DESTROYS std::vector/string semantics)
═══════════════════════════════════════════════════════════════════════════════

For C++ with std::vector<float>:
• Ghidra may show "void func(vector)" but it should be "float func(vector<float>)"
• Ghidra may discard return values from std::abs() - YOU MUST ACCUMULATE THEM
• Ghidra may show operator[] calls but lose the accumulation logic

If you see std::vector + addss/divss assembly → function returns float!
If you see two loops with divss → Mean Absolute Deviation, returns float!

═══════════════════════════════════════════════════════════════════════════════
ASSEMBLY (GROUND TRUTH - this is what the binary ACTUALLY does):
═══════════════════════════════════════════════════════════════════════════════
```asm
{truncated_asm}
```

═══════════════════════════════════════════════════════════════════════════════
GHIDRA PSEUDOCODE (UNRELIABLE - use as rough guide only, may be WRONG):
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

VERIFICATION: ✗ DIFFERENT (your code doesn't match the binary's behavior)
"""
    
    # V7.1: Add history of previous attempts to avoid repeating mistakes
    if code_history and len(code_history) > 0:
        prompt += "\n═══════════════════════════════════════════════════════════════════════════════\n"
        prompt += "PREVIOUS FAILED ATTEMPTS (DO NOT REPEAT THESE MISTAKES):\n"
        prompt += "═══════════════════════════════════════════════════════════════════════════════\n"
        for i, (prev_code, prev_div) in enumerate(code_history[-MAX_CODE_HISTORY:]):
            # Truncate previous attempts aggressively to fit context
            prev_truncated = prev_code[:3000] if prev_code else ""
            if prev_code and len(prev_code) > 3000:
                prev_truncated += "\n// ... (truncated)"
            prompt += f"\nAttempt {i+1} ({prev_div} divergences) - ALREADY TRIED, FAILED:\n"
            prompt += f"```{language}\n{prev_truncated}\n```\n"
        prompt += "\n⚠️ DO NOT recreate any of the above attempts. Try a DIFFERENT approach.\n"
    
    # Add type constraints if available
    type_str = format_type_constraints_for_prompt(type_constraints)
    if type_str:
        prompt += f"""
═══════════════════════════════════════════════════════════════════════════════
TYPE CONSTRAINTS (from binary analysis - more reliable than Ghidra):
═══════════════════════════════════════════════════════════════════════════════
{type_str}

⚠️ USE THESE TYPES! If your types don't match, that's likely your bug.
"""
    
    # V7.2: Add LLM-as-judge signature analysis
    if signature_analysis:
        prompt += f"""
═══════════════════════════════════════════════════════════════════════════════
🔍 SIGNATURE ANALYSIS (LLM-as-judge identified these Ghidra errors):
═══════════════════════════════════════════════════════════════════════════════
{signature_analysis[:1500]}

⚠️ THIS ANALYSIS IDENTIFIED SPECIFIC GHIDRA ERRORS! Use it to fix your code.
If it says return type should be float (not void), CHANGE YOUR RETURN TYPE!
"""
    
    # Format divergences with clear explanation - show up to 5 counterexamples
    if vexhelix_result.divergences:
        prompt += "\n═══════════════════════════════════════════════════════════════════════════════\n"
        prompt += "COUNTEREXAMPLES (inputs where your code gives WRONG answer):\n"
        prompt += "═══════════════════════════════════════════════════════════════════════════════\n"
        for i, div in enumerate(vexhelix_result.divergences[:5]):
            prompt += f"\nTest case {i+1}:\n"
            if div.get('inputs'):
                prompt += "  Inputs: "
                inputs_str = ", ".join([f"{inp.get('name', 'arg')}={inp.get('value', '?')}" for inp in div['inputs']])
                prompt += inputs_str + "\n"
            if div.get('orig_output'):
                orig = div['orig_output']
                prompt += f"  ✓ Expected (from binary): {orig.get('value', '?')}"
                if orig.get('hex'):
                    prompt += f" (0x{orig.get('hex', '?')})"
                prompt += "\n"
            if div.get('dec_output'):
                dec = div['dec_output']
                prompt += f"  ✗ Your output: {dec.get('value', '?')}"
                if dec.get('hex'):
                    prompt += f" (0x{dec.get('hex', '?')})"
                prompt += "\n"
    
    prompt += """
═══════════════════════════════════════════════════════════════════════════════
YOUR TASK: Fix the code to match ASSEMBLY behavior
═══════════════════════════════════════════════════════════════════════════════

Steps:
1. CHECK RETURN TYPE FIRST - if assembly has xmm0/eax before ret, function returns a value!
2. If function COMPUTES something, it MUST RETURN it - ignore Ghidra's void!
3. Analyze the ASSEMBLY to understand what the function REALLY does
4. Use TYPE CONSTRAINTS if provided - they're more reliable than Ghidra (BUT override void if assembly disagrees)
5. Check COUNTEREXAMPLES - understand WHY your code gives wrong output
6. DO NOT repeat previous failed attempts - try a DIFFERENT approach
7. For C++ STL: if assembly shows float ops, the function returns float even if Ghidra says void!
8. Rewrite based on assembly semantics, not Ghidra artifacts

Output ONLY the corrected function code. No explanations."""
    return prompt


# =============================================================================
# COMPILATION UTILITIES
# =============================================================================

def get_optimization_level(opt_str: str) -> OptimizationLevel:
    """
    Convert optimization level string to OptimizationLevel enum.
    
    Args:
        opt_str: String like "O0", "O1", "O2", "O3"
        
    Returns:
        OptimizationLevel enum value, defaults to O0 if not recognized
    """
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


def compile_code(c_code: str, language: str, temp_dir: Path, opt: str = "O0") -> Tuple[bool, str, Optional[Path]]:
    """
    Compile code and return (success, message, executable_path).
    
    Args:
        c_code: The C/C++ code to compile
        language: "c" or "cpp"
        temp_dir: Directory for temporary files
        opt: Optimization level string ("O0", "O1", "O2", "O3")
    """
    file_extension = "cpp" if language == "cpp" else "c"
    source_file = temp_dir / f"code.{file_extension}"
    executable_path = temp_dir / "executable.out"
    
    with open(source_file, "w") as f:
        f.write(c_code)
    
    opt_level = get_optimization_level(opt)
    status, message = c.compile_source(
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


def compile_single_program(data: Dict, temp_base_dir: Path) -> CompilationResult:
    """Compile a single program (original code) and return the result."""
    try:
        c_program = data['func_dep'] + data['func']
        temp_dir = temp_base_dir / f"prog_{data['index']}"
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        c_file_path = temp_dir / f"temp.{'cpp' if data['language']=='cpp' else 'c'}"
        executable_path = temp_dir / f"temp_executable_{data['index']}"
        
        with open(c_file_path, "w") as f:
            f.write(c_program)
        
        # Use the optimization level from testcase data (V7 FIX: was hardcoded to O0)
        opt_level = get_optimization_level(data.get('opt', 'O0'))
        status, message = c.compile_source(
            source_file_path=str(c_file_path),
            output_file_path=str(executable_path),
            opt=opt_level,
            is_cpp=(data['language'] == "cpp"),
            c_flag=True
        )
        
        if not status:
            print(f"[Compile] Failed for index {data['index']}: {message[:100]}")
            return CompilationResult(
                index=data['index'], success=False, executable_path=None,
                error_message=message, data=data
            )
        
        return CompilationResult(
            index=data['index'], success=True, executable_path=executable_path,
            error_message=None, data=data
        )
    
    except Exception as e:
        print(f"[Compile] Exception for index {data['index']}: {e}")
        return CompilationResult(
            index=data['index'], success=False, executable_path=None,
            error_message=str(e), data=data
        )


# =============================================================================
# BATCH OPERATIONS
# =============================================================================

def batch_compile_programs(items: List[Dict], temp_base_dir: Path) -> List[CompilationResult]:
    """Compile multiple programs in parallel."""
    print(f"\n[Batch Compile] Starting compilation of {len(items)} programs...")
    results = []
    
    with ThreadPoolExecutor(max_workers=COMPILATION_BATCH_SIZE) as executor:
        futures = {
            executor.submit(compile_single_program, item, temp_base_dir): item 
            for item in items
        }
        
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if result.success:
                lang = result.data.get('language', 'c')
                print(f"[Batch Compile] ✓ Index {result.index} ({lang}) compiled successfully")
            else:
                print(f"[Batch Compile] ✗ Index {result.index} failed")
    
    successful = sum(1 for r in results if r.success)
    c_count = sum(1 for r in results if r.success and r.data.get('language') == 'c')
    cpp_count = sum(1 for r in results if r.success and r.data.get('language') == 'cpp')
    print(f"[Batch Compile] Completed: {successful}/{len(items)} successful (C: {c_count}, C++: {cpp_count})\n")
    return results


def batch_ghidra_analysis(executables: List[Tuple[int, Path]]) -> Dict[int, Dict]:
    """Run Ghidra analysis on multiple executables in batch."""
    print(f"\n[Batch Ghidra] Starting analysis of {len(executables)} executables...")
    results = {}
    
    cfg_script = Path(__file__).resolve().parent.parent / "src" / "scripts" / "batched_cfg_extractor.py"
    callgraph_script = Path(__file__).resolve().parent.parent / "src" / "scripts" / "batched_call_graph_extractor.py"
    
    for i in range(0, len(executables), GHIDRA_BATCH_SIZE):
        batch = executables[i:i + GHIDRA_BATCH_SIZE]
        print(f"[Batch Ghidra] Processing batch {i//GHIDRA_BATCH_SIZE + 1} ({len(batch)} executables)...")
        
        with ThreadPoolExecutor(max_workers=GHIDRA_BATCH_SIZE) as executor:
            futures = {}
            
            for idx, exe_path in batch:
                future = executor.submit(analyze_single_executable, idx, exe_path, cfg_script, callgraph_script)
                futures[future] = idx
            
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    result = future.result()
                    results[idx] = result
                    print(f"[Batch Ghidra] ✓ Index {idx} analyzed successfully")
                except Exception as e:
                    print(f"[Batch Ghidra] ✗ Index {idx} failed: {e}")
                    results[idx] = None
    
    print(f"[Batch Ghidra] Completed analysis of {len(results)} executables\n")
    return results


def analyze_single_executable(idx: int, exe_path: Path, cfg_script: Path, callgraph_script: Path) -> Dict:
    """Analyze a single executable with Ghidra."""
    executable_name = exe_path.stem
    output_dir_path = Path(config["humaneval"]["output_path"]) / "SOG" / executable_name
    if output_dir_path.exists():
        shutil.rmtree(output_dir_path)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    
    cfg_map = g.extract_cfg(exe_path, output_dir_path)
    callgraph_map = g.extract_call_graph(exe_path, output_dir_path)
    
    return {
        'cfg_map': cfg_map,
        'callgraph_map': callgraph_map,
        'output_dir': output_dir_path,
        'executable_name': executable_name
    }


def gen_code_summary_batch(prompts: List[Tuple[int, str]]) -> Dict[int, str]:
    """Generate code summaries for multiple functions in batch."""
    print(f"\n[Batch LLM] Generating {len(prompts)} summaries...")
    results = {}
    
    with ThreadPoolExecutor(max_workers=LLM_BATCH_SIZE) as executor:
        futures = {}
        for idx, prompt in prompts:
            future = executor.submit(llm_interface.generate, prompt)
            futures[future] = idx
        
        for future in as_completed(futures):
            idx = futures[future]
            try:
                result = future.result()
                results[idx] = result
                print(f"[Batch LLM] ✓ Summary {idx} generated")
            except Exception as e:
                print(f"[Batch LLM] ✗ Summary {idx} failed: {e}")
                results[idx] = ""
    
    print(f"[Batch LLM] Completed {len(results)} summaries\n")
    return results


def gen_context_summary(callgraph: Dict[str, List[str]]) -> str:
    """Generate caller/callee context summary."""
    prompt = ""
    for function, callees in callgraph.items():
        if function == "func0":
            prompt += f"{function} calls {', '.join(callees) if callees else 'no functions'}\n"
    return prompt


# =============================================================================
# MAIN OPTIMIZATION LOOP WITH VEXHELIX + TYPEFORGE
# =============================================================================

def get_optimized_code_v7(
    c_code: str,
    function_summary: str,
    caller_and_callee_summary: str,
    function_sog: str,
    type_constraints: Dict,
    language: str,
    llm_interface: LLMInterface,
    original_binary_path: Path,
    function_name: str,
    original_asm: str,
    original_ghidra: str,
    opt: str = "O0",
    num_args: int = 3,
    task_id: str = "",
    signature_analysis: str = ""  # V7.2: LLM-as-judge signature analysis
) -> Tuple[bool, str, Dict]:
    """
    Enhanced optimization with VexHelix semantic verification + TypeForge type constraints.
    
    V7 KEY IMPROVEMENT: Type constraints from TypeForge are included in ALL prompts.
    V7.2 IMPROVEMENT: LLM-as-judge signature analysis included to catch Ghidra errors early.
    
    This addresses a fundamental limitation:
    - VexHelix can only verify semantic equivalence for explored paths
    - Type errors may not manifest in symbolic execution but cause runtime bugs
    - TypeForge provides ground truth types from binary analysis
    
    The repair loop:
    1. Attempts static repair until code compiles (with type hints)
    2. Verifies semantic equivalence with VexHelix
    3. Performs semantic repair if divergences found (with type hints)
    4. Early exit if divergence count stagnates
    
    Returns:
        (success, optimized_code, stats)
    """
    prefix = f"[{task_id}]" if task_id else "[Optimize V7]"
    
    stats = {
        'static_repair_iterations': 0,
        'semantic_repair_iterations': 0,
        'vexhelix_calls': 0,
        'vexhelix_equivalent_achieved': False,
        'final_result': None,
        'language': language,
        'divergence_history': [],
        'has_type_constraints': bool(type_constraints)  # Track if TypeForge data was available
    }
    
    # Track divergence improvement
    best_divergence_count = float('inf')
    stagnant_count = 0
    
    # V7.1: Track BEST code version (compilable + fewest divergences)
    best_code = None
    best_code_divergences = float('inf')
    
    # V7.1: History of recent attempts to avoid repeating mistakes
    code_history = []  # List of (code, divergence_count) tuples
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Initial LLM prompt - NOW INCLUDES ASSEMBLY + TYPE CONSTRAINTS
        print(f"{prefix} Starting optimization for {function_name} ({language})...", flush=True)
        if type_constraints:
            print(f"{prefix} TypeForge constraints available ✓", flush=True)
        else:
            print(f"{prefix} No TypeForge constraints (relying on assembly)", flush=True)
        
        # V7.2: Log signature analysis status
        if signature_analysis:
            print(f"{prefix} LLM-as-judge signature analysis available ✓", flush=True)
        
        initial_prompt = get_initial_prompt(
            c_code=c_code,
            function_summary=function_summary,
            caller_and_callee_summary=caller_and_callee_summary,
            function_sog=function_sog,
            type_constraints=type_constraints,
            language=language,
            asm=original_asm,
            signature_analysis=signature_analysis  # V7.2: LLM-as-judge result
        )
        
        # Initial LLM generation - must succeed
        try:
            optimized_code = llm_interface.generate(initial_prompt)
            if not optimized_code.strip():
                raise RuntimeError("LLM returned empty response for initial prompt")
        except Exception as e:
            print(f"{prefix} ERROR: Initial LLM generation failed: {e}")
            stats['final_result'] = 'llm_error'
            return False, c_code, stats  # Return original Ghidra code as fallback
        
        # Track the last known good (compilable) code
        last_compilable_code = None
        
        # Main repair loop
        for iteration in range(MAX_REPAIR_ITERATIONS):
            print(f"{prefix} === Iteration {iteration + 1}/{MAX_REPAIR_ITERATIONS} ===")
            
            # Phase 1: Static Repair (ensure compilation)
            compile_success, compile_message, executable_path = compile_code(
                optimized_code, language, temp_path, opt
            )
            
            if not compile_success:
                print(f"{prefix} [Static] Code doesn't compile, fixing...")
                stats['static_repair_iterations'] += 1
                
                e = ErrorNormalizer()
                error_prompt = e.format_for_llm(compile_message)
                
                repair_prompt = get_static_repair_prompt(
                    c_code=optimized_code,
                    compilation_errors=error_prompt,
                    function_summary=function_summary,
                    caller_and_callee_summary=caller_and_callee_summary,
                    function_sog=function_sog,
                    type_constraints=type_constraints,
                    language=language
                )
                
                try:
                    new_code = llm_interface.generate(repair_prompt)
                    if new_code.strip():
                        optimized_code = new_code
                    else:
                        print(f"{prefix} [Static] LLM returned empty, keeping previous code")
                except Exception as e:
                    print(f"{prefix} [Static] LLM error: {e}, keeping previous code")
                print(f"{prefix} [Static] Received repaired code")
                continue
            
            print(f"{prefix} [Static] ✓ Compiles")
            
            # Phase 2: Semantic Verification (VexHelix)
            print(f"{prefix} [Semantic] Calling VexHelix...")
            stats['vexhelix_calls'] += 1
            
            vexhelix_result = call_vexhelix_api(
                binary_path=original_binary_path,
                decompiled_code=optimized_code,
                function_name=function_name,
                language=language,
                num_args=num_args,
                loop_bound=5
            )
            
            if not vexhelix_result.success and vexhelix_result.status == 'error':
                if vexhelix_result.compilation_error:
                    print(f"{prefix} [Semantic] VexHelix compile error, fixing...")
                    stats['static_repair_iterations'] += 1
                    
                    repair_prompt = get_static_repair_prompt(
                        c_code=optimized_code,
                        compilation_errors=vexhelix_result.compilation_error,
                        function_summary=function_summary,
                        caller_and_callee_summary=caller_and_callee_summary,
                        function_sog=function_sog,
                        type_constraints=type_constraints,
                        language=language
                    )
                    try:
                        new_code = llm_interface.generate(repair_prompt)
                        if new_code.strip():
                            optimized_code = new_code
                    except Exception as e:
                        print(f"{prefix} [Semantic] LLM error on VexHelix compile fix: {e}")
                    continue
                
                print(f"{prefix} [Semantic] VexHelix API error: {vexhelix_result.error_message}")
                stats['final_result'] = 'vexhelix_error'
                # Return current optimized_code (even if it's the last compilable version)
                return True, optimized_code if optimized_code.strip() else c_code, stats
            
            if vexhelix_result.status == 'timeout':
                print(f"{prefix} [Semantic] VexHelix timeout")
                stats['final_result'] = 'vexhelix_timeout'
                return True, optimized_code, stats
            
            if vexhelix_result.status == 'equivalent' or vexhelix_result.equivalent:
                print(f"{prefix} ✓✓✓ EQUIVALENT!")
                stats['vexhelix_equivalent_achieved'] = True
                stats['final_result'] = 'equivalent'
                return True, optimized_code, stats
            
            # Code compiled and VexHelix ran - save as last known good
            last_compilable_code = optimized_code
            
            # Phase 3: Check for stagnation and track best code
            current_divergences = len(vexhelix_result.divergences or [])
            stats['divergence_history'].append(current_divergences)
            print(f"{prefix} [Semantic] ✗ DIFFERENT - {current_divergences} divergences")
            
            # V7.1: Track best code (compilable + fewest divergences)
            if current_divergences < best_code_divergences:
                best_code = optimized_code
                best_code_divergences = current_divergences
                print(f"{prefix} [Semantic] New best code saved ({current_divergences} divergences)")
            
            # V7.1: Add to history for context in repair prompt
            code_history.append((optimized_code, current_divergences))
            if len(code_history) > MAX_CODE_HISTORY:
                code_history.pop(0)  # Keep only recent history
            
            if current_divergences < best_divergence_count:
                best_divergence_count = current_divergences
                stagnant_count = 0
                print(f"{prefix} [Semantic] Improvement! Best so far: {best_divergence_count}")
            else:
                stagnant_count += 1
                print(f"{prefix} [Semantic] No improvement ({stagnant_count}/{MAX_STAGNANT_ITERATIONS})")
                
                if stagnant_count >= MAX_STAGNANT_ITERATIONS:
                    print(f"{prefix} [Semantic] ⚠ Stagnation detected - returning best code")
                    stats['final_result'] = 'stagnant_divergences'
                    # V7.1: Return BEST code, not current code
                    final_code = best_code if best_code else optimized_code
                    return True, final_code, stats
            
            # Phase 4: Semantic Repair (V7.1: with TYPE CONSTRAINTS + HISTORY)
            print(f"{prefix} [Semantic] Attempting fix with type constraints + history...")
            stats['semantic_repair_iterations'] += 1
            
            # V7.2: Pass history and signature_analysis to avoid repeating mistakes
            semantic_prompt = get_semantic_repair_prompt(
                original_asm=original_asm,
                original_ghidra=original_ghidra,
                current_code=optimized_code,
                function_summary=function_summary,
                vexhelix_result=vexhelix_result,
                type_constraints=type_constraints,
                language=language,
                code_history=code_history,  # V7.1: previous attempts
                signature_analysis=signature_analysis  # V7.2: LLM-as-judge result
            )
            
            try:
                # V7.1: Capture reasoning for debugging/analysis
                result = llm_interface.generate(semantic_prompt, return_reasoning=True)
                if isinstance(result, dict):
                    new_code = result.get('output', '')
                    # Store reasoning in stats for later analysis
                    if 'semantic_repair_reasoning' not in stats:
                        stats['semantic_repair_reasoning'] = []
                    stats['semantic_repair_reasoning'].append({
                        'iteration': iteration,
                        'reasoning': result.get('reasoning'),
                        'usage': result.get('usage')
                    })
                else:
                    new_code = result  # Fallback for non-dict response
                    
                if new_code.strip():
                    optimized_code = new_code
                else:
                    print(f"{prefix} [Semantic] LLM returned empty, keeping previous code")
            except Exception as e:
                print(f"{prefix} [Semantic] LLM error: {e}, keeping previous code")
            print(f"{prefix} [Semantic] Received repaired code")
        
        # Max iterations reached - return BEST code
        print(f"{prefix} Max iterations ({MAX_REPAIR_ITERATIONS}) reached")
        
        # V7.1: Return best code, not current code
        final_code = best_code if best_code else (last_compilable_code if last_compilable_code else optimized_code)
        compile_success, _, _ = compile_code(final_code, language, temp_path, opt)
        
        if compile_success:
            stats['final_result'] = 'max_iterations_compilable'
            return True, final_code, stats
        else:
            # Fall back to last compilable code
            stats['final_result'] = 'max_iterations_not_compilable'
            fallback_code = last_compilable_code if last_compilable_code else optimized_code
            return False, fallback_code, stats


# =============================================================================
# DATA ENRICHMENT (V7: INCLUDES TYPE CONSTRAINTS)
# =============================================================================

def split_enrichment(data: Dict, ghidra_result: Dict, original_binary_path: Path) -> Dict:
    """
    Enrich function data using pre-extracted Ghidra analysis.
    
    V7 IMPROVEMENT: Also loads TypeForge type constraints.
    """
    program_data = {}
    program_data['index'] = data['index']
    program_data['language'] = data['language']
    program_data['executable_name'] = ghidra_result['executable_name']
    program_data['opt'] = data['opt']
    program_data['test'] = data['test']
    program_data['original_code'] = data['func']
    program_data['func_dep'] = data['func_dep']
    program_data['original_binary_path'] = str(original_binary_path)

    program_data['functions'] = []
    
    cfg_map = ghidra_result['cfg_map']
    callgraph_map = ghidra_result['callgraph_map']
    
    # Build call graph if available
    if 'call_graph' in callgraph_map and callgraph_map['call_graph']:
        callgraph = build_call_graph(callgraph_map['call_graph'])
        sorted_functions = topological_sort(callgraph)
    else:
        callgraph = {}
        sorted_functions = []
    
    if len(sorted_functions) == 0:
        sorted_functions.append("func0")
    
    program_data['callgraph'] = callgraph
    
    functions = []
    for function_name in sorted_functions:
        if function_name != "func0":
            continue
        
        f_data = {}
        f_data['f_name'] = function_name
        f_data['asm'] = data['asm']
        f_data['ghidra_code'] = data['ghidra_pseudo']
        
        # V7: Load TypeForge type constraints with Typehoon fallback
        f_data['type_constraints'] = get_type_constraints(data, str(original_binary_path))
        
        sog_path = cfg_map.get(function_name)
        if sog_path:
            with open(sog_path, 'r') as f:
                f_data['sog_dot'] = f.read()
        else:
            f_data['sog_dot'] = ""
        
        callers = [caller for caller, callees in callgraph.items() if function_name in callees]
        callees = callgraph.get(function_name, [])
        f_data['callers'] = callers
        f_data['callees'] = callees
        
        functions.append(f_data)
    
    program_data['functions'] = functions
    return program_data


# =============================================================================
# BATCH OPTIMIZATION WITH STREAMING PARALLEL REPAIR
# =============================================================================

def batch_optimize_functions_v7(enriched_programs: List[Dict]) -> List[Dict]:
    """
    Optimize multiple functions using STREAMING PARALLEL repair loops.
    
    V7: Uses TypeForge type constraints in addition to VexHelix verification.
    """
    global active_count, completed_count, total_tasks
    
    print(f"\n{'='*70}")
    print(f"[Batch Optimize V7] STREAMING PARALLEL with TypeForge + VexHelix")
    print(f"[Batch Optimize V7] Programs: {len(enriched_programs)}")
    print(f"[Batch Optimize V7] Concurrent workers: {PARALLEL_REPAIR_WORKERS}")
    print(f"[Batch Optimize V7] Rate limit: {GLOBAL_RATE_LIMITER.max_rpm} requests/min")
    print(f"{'='*70}")
    
    # Step 1: Batch generate summaries first
    summary_prompts = []
    for prog_idx, prog_data in enumerate(enriched_programs):
        for func_data in prog_data['functions']:
            summary_prompt = config["prompts"]["summary_prompt"]
            prompt = f"{summary_prompt}"
            if func_data.get('ghidra_code'):
                prompt += f"\n\nGhidra Code:\n```c\n{func_data['ghidra_code']}\n```"
            if func_data.get('asm'):
                prompt += f"\n\nAssembly Instructions:\n{func_data['asm'][:2000]}"
            summary_prompts.append((prog_idx, prompt))
    
    summaries = gen_code_summary_batch(summary_prompts)
    
    # Step 2: Add summaries to function data
    for prog_idx, prog_data in enumerate(enriched_programs):
        for func_data in prog_data['functions']:
            func_data['function_summary'] = summaries.get(prog_idx, "")
    
    # Step 3: Build list of tasks
    optimization_tasks = []
    type_constraint_count = 0
    for prog_idx, prog_data in enumerate(enriched_programs):
        for func_data in prog_data['functions']:
            if func_data.get('type_constraints'):
                type_constraint_count += 1
            task = {
                'prog_idx': prog_idx,
                'prog_data': prog_data,
                'func_data': func_data,
                'task_id': f"P{prog_data.get('index', prog_idx)}"
            }
            optimization_tasks.append(task)
    
    total_tasks = len(optimization_tasks)
    active_count = 0
    completed_count = 0
    
    print(f"\n[V7] TypeForge constraints available for {type_constraint_count}/{total_tasks} programs")
    print(f"[Streaming] Starting execution...\n")
    
    # Step 4: Run full repair loops in parallel
    results_map = {}
    
    def run_single_optimization(task):
        global active_count, completed_count
        
        prog_data = task['prog_data']
        func_data = task['func_data']
        prog_idx = task['prog_idx']
        task_id = task['task_id']
        lang = prog_data.get('language', 'c')
        idx = prog_data.get('index', prog_idx)
        has_types = "T" if func_data.get('type_constraints') else "-"
        
        with print_lock:
            active_count += 1
            print(f"  [START] {task_id} ({lang}) [{has_types}] idx={idx} - active: {active_count}", flush=True)
        
        start_time = time.time()
        
        try:
            # V7 FIX: Pass optimization level from testcase data (was hardcoded to O0)
            opt_level = prog_data.get('opt', 'O0')
            optimization_success, optimized_code, stats = get_optimized_code_v7(
                c_code=func_data['ghidra_code'],
                function_summary=func_data['function_summary'],
                caller_and_callee_summary=gen_context_summary(prog_data['callgraph']),
                function_sog="",
                type_constraints=func_data.get('type_constraints', {}),
                language=lang,
                llm_interface=llm_interface,
                original_binary_path=Path(prog_data['original_binary_path']),
                function_name=func_data['f_name'],
                original_asm=func_data.get('asm', ''),
                original_ghidra=func_data['ghidra_code'],
                opt=opt_level,
                num_args=3,
                task_id=task_id
            )
            
            duration = time.time() - start_time
            stats['duration'] = duration
            
            with print_lock:
                active_count -= 1
                completed_count += 1
                status = stats.get('final_result', 'unknown')
                sym = "✓" if status == 'equivalent' else "✗"
                print(f"[{sym}] {task_id} ({lang}) [{has_types}]: {status} "
                      f"({stats.get('semantic_repair_iterations', 0)}it, "
                      f"{stats.get('vexhelix_calls', 0)}vex, {duration:.1f}s) | "
                      f"done: {completed_count}/{total_tasks}, active: {active_count}", flush=True)
            
            return {
                'prog_idx': prog_idx,
                'success': optimization_success,
                'optimized_code': optimized_code,
                'stats': stats
            }
        except Exception as e:
            duration = time.time() - start_time
            with print_lock:
                active_count -= 1
                completed_count += 1
                print(f"[✗] {task_id} ({lang}): exception ({duration:.1f}s) - {str(e)[:100]} | "
                      f"done: {completed_count}/{total_tasks}, active: {active_count}", flush=True)
            return {
                'prog_idx': prog_idx,
                'success': False,
                'optimized_code': "",
                'stats': {'final_result': 'exception', 'error': str(e), 'duration': duration}
            }
    
    # Execute in parallel
    executor = ThreadPoolExecutor(max_workers=PARALLEL_REPAIR_WORKERS)
    try:
        futures = {
            executor.submit(run_single_optimization, task): task
            for task in optimization_tasks
        }
        
        for future in as_completed(futures):
            try:
                result = future.result()
                prog_idx = result['prog_idx']
                results_map[prog_idx] = result
            except Exception as e:
                task = futures[future]
                print(f"[ERROR] Task P{task['prog_idx']} future exception: {e}", flush=True)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    
    # Step 5: Update enriched_programs with results
    for prog_idx, prog_data in enumerate(enriched_programs):
        result = results_map.get(prog_idx)
        if result:
            for func_data in prog_data['functions']:
                func_data['optimization_status'] = result['success']
                func_data['optimized_code'] = result['optimized_code']
                func_data['optimization_stats'] = result['stats']
        else:
            for func_data in prog_data['functions']:
                func_data['optimization_status'] = False
                func_data['optimized_code'] = ""
                func_data['optimization_stats'] = {'final_result': 'no_result'}
    
    # Print comprehensive summary including rate limiter stats
    equivalent_count = sum(1 for r in results_map.values() 
                          if r['stats'].get('final_result') == 'equivalent')
    
    # TypeForge impact analysis
    with_types_equiv = sum(1 for r in results_map.values() 
                          if r['stats'].get('final_result') == 'equivalent' 
                          and r['stats'].get('has_type_constraints'))
    with_types_total = sum(1 for r in results_map.values() 
                          if r['stats'].get('has_type_constraints'))
    without_types_equiv = equivalent_count - with_types_equiv
    without_types_total = len(results_map) - with_types_total
    
    # Get rate limiter stats
    rl_stats = GLOBAL_RATE_LIMITER.get_stats()
    
    print(f"\n{'='*70}")
    print(f"[Batch Optimize V7] Complete!")
    print(f"{'='*70}")
    print(f"  Equivalent: {equivalent_count}/{total_tasks} ({100*equivalent_count/total_tasks:.0f}%)")
    print(f"  TypeForge Impact:")
    print(f"    With TypeForge:    {with_types_equiv}/{with_types_total} ({100*with_types_equiv/with_types_total if with_types_total else 0:.0f}%)")
    print(f"    Without TypeForge: {without_types_equiv}/{without_types_total} ({100*without_types_equiv/without_types_total if without_types_total else 0:.0f}%)")
    print(f"  Rate Limiter:")
    print(f"    Total LLM requests: {rl_stats['total_requests']}")
    print(f"    Total wait time: {rl_stats['total_wait_time_seconds']}s")
    print(f"{'='*70}\n")
    
    return enriched_programs


# =============================================================================
# PIPELINED ARCHITECTURE - TRUE CPU-STYLE PIPELINE (V7)
# =============================================================================
# 
# ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
# │  COMPILE    │──►│   GHIDRA    │──►│  SUMMARIES  │──►│  VEXHELIX   │
# │  width=20   │   │  width=12   │   │  width=12   │   │  width=12   │
# └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
#       ↑                 ↑                 ↑                 ↑
#   compile_q         ghidra_q          summary_q         vexhelix_q
#
# Each stage pulls from its input queue, processes, pushes to next queue.
# Stages run CONCURRENTLY - no waiting for all items to complete a stage!
# V7: TypeForge constraints loaded during enrichment
# V7: Rate limiter ensures LLM requests don't exceed limit
# =============================================================================

# Sentinel value to signal stage shutdown
PIPELINE_DONE = object()


def _pipeline_compile_stage_v7(
    input_q: Queue, 
    output_q: Queue, 
    temp_base_dir: Path,
    dropped_counter: Dict,
    counter_lock: threading.Lock,
    stage_id: str = "COMPILE"
):
    """Pipeline Stage 1: Compile programs."""
    def worker():
        while True:
            item = input_q.get()
            if item is PIPELINE_DONE:
                input_q.task_done()
                break
            
            try:
                data = item
                idx = data['index']
                lang = data.get('language', 'c')
                
                with print_lock:
                    print(f"[{stage_id}] P{idx} ({lang}) compiling...", flush=True)
                
                result = compile_single_program(data, temp_base_dir)
                
                if result.success:
                    with print_lock:
                        print(f"[{stage_id}] P{idx} ({lang}) ✓", flush=True)
                    output_q.put({
                        'data': data,
                        'compile_result': result
                    })
                else:
                    with counter_lock:
                        dropped_counter['compile'] += 1
                    with print_lock:
                        print(f"[{stage_id}] P{idx} ({lang}) ✗ compile failed (dropped)", flush=True)
            except Exception as e:
                with counter_lock:
                    dropped_counter['compile'] += 1
                with print_lock:
                    print(f"[{stage_id}] P{item.get('index', '?')} exception: {e} (dropped)", flush=True)
            finally:
                input_q.task_done()
    
    return worker


def _pipeline_ghidra_stage_v7(
    input_q: Queue, 
    output_q: Queue, 
    cfg_script: Path,
    callgraph_script: Path,
    dropped_counter: Dict,
    counter_lock: threading.Lock,
    stage_id: str = "GHIDRA"
):
    """Pipeline Stage 2: Ghidra analysis."""
    def worker():
        while True:
            item = input_q.get()
            if item is PIPELINE_DONE:
                input_q.task_done()
                break
            
            try:
                data = item['data']
                compile_result = item['compile_result']
                idx = data['index']
                lang = data.get('language', 'c')
                
                with print_lock:
                    print(f"[{stage_id}] P{idx} ({lang}) analyzing...", flush=True)
                
                ghidra_result = analyze_single_executable(
                    idx, 
                    compile_result.executable_path, 
                    cfg_script, 
                    callgraph_script
                )
                
                if ghidra_result is not None:
                    with print_lock:
                        print(f"[{stage_id}] P{idx} ({lang}) ✓", flush=True)
                    output_q.put({
                        'data': data,
                        'compile_result': compile_result,
                        'ghidra_result': ghidra_result
                    })
                else:
                    with counter_lock:
                        dropped_counter['ghidra'] += 1
                    with print_lock:
                        print(f"[{stage_id}] P{idx} ({lang}) ✗ ghidra failed (dropped)", flush=True)
            except Exception as e:
                with counter_lock:
                    dropped_counter['ghidra'] += 1
                with print_lock:
                    print(f"[{stage_id}] P{item['data'].get('index', '?')} exception: {e} (dropped)", flush=True)
            finally:
                input_q.task_done()
    
    return worker


def _pipeline_summary_stage_v7(
    input_q: Queue, 
    output_q: Queue, 
    dropped_counter: Dict,
    counter_lock: threading.Lock,
    stage_id: str = "SUMMARY"
):
    """Pipeline Stage 3: LLM summary generation (V7: with TypeForge enrichment)."""
    def worker():
        while True:
            item = input_q.get()
            if item is PIPELINE_DONE:
                input_q.task_done()
                break
            
            try:
                data = item['data']
                compile_result = item['compile_result']
                ghidra_result = item['ghidra_result']
                idx = data['index']
                lang = data.get('language', 'c')
                
                with print_lock:
                    print(f"[{stage_id}] P{idx} ({lang}) generating...", flush=True)
                
                # V7: Enrich data with ghidra results AND TypeForge constraints
                enriched_data = split_enrichment(data, ghidra_result, compile_result.executable_path)
                
                # Generate summaries AND signature analysis for all functions
                for func_data in enriched_data['functions']:
                    # ═══════════════════════════════════════════════════════════════
                    # STEP 1: LLM-AS-JUDGE SIGNATURE ANALYSIS (Option A)
                    # Analyze Ghidra's likely mistakes BEFORE generating summary
                    # ═══════════════════════════════════════════════════════════════
                    sig_analysis_prompt = config["prompts"].get("signature_analysis_prompt", "")
                    if sig_analysis_prompt:
                        sig_prompt = f"{sig_analysis_prompt}"
                        if func_data.get('ghidra_code'):
                            sig_prompt += f"\n\nGhidra Decompiled Code:\n```c\n{func_data['ghidra_code']}\n```"
                        if func_data.get('asm'):
                            sig_prompt += f"\n\nAssembly (GROUND TRUTH - check xmm0/eax before RET!):\n```asm\n{func_data['asm'][:3000]}\n```"
                        # Include TypeHoon constraints for signature validation
                        if func_data.get('type_constraints'):
                            sig_prompt += f"\n\nTypeHoon Type Constraints:\n{json.dumps(func_data['type_constraints'], indent=2)[:2000]}"
                        
                        try:
                            func_data['signature_analysis'] = llm_interface.generate(sig_prompt)
                        except Exception as e:
                            func_data['signature_analysis'] = f"Error: {e}"
                    else:
                        func_data['signature_analysis'] = ""
                    
                    # ═══════════════════════════════════════════════════════════════
                    # STEP 2: ENHANCED SUMMARY GENERATION (Option B)
                    # Include TypeHoon + signature analysis for better summaries
                    # ═══════════════════════════════════════════════════════════════
                    summary_prompt = config["prompts"]["summary_prompt"]
                    prompt = f"{summary_prompt}"
                    
                    # Add Ghidra code
                    if func_data.get('ghidra_code'):
                        prompt += f"\n\nGhidra Decompiled Code (MAY BE WRONG - especially return type!):\n```c\n{func_data['ghidra_code']}\n```"
                    
                    # Add TypeHoon constraints (Option B enhancement)
                    if func_data.get('type_constraints'):
                        prompt += f"\n\nTypeHoon Type Constraints (from binary analysis):\n{json.dumps(func_data['type_constraints'], indent=2)[:1500]}"
                    
                    # Add signature analysis from LLM-as-judge (Option A result)
                    if func_data.get('signature_analysis'):
                        prompt += f"\n\nSignature Analysis (LLM-as-judge result):\n{func_data['signature_analysis'][:1000]}"
                    
                    # Add assembly (ground truth)
                    if func_data.get('asm'):
                        prompt += f"\n\nAssembly Instructions (GROUND TRUTH - check xmm0/eax before RET for return type!):\n```asm\n{func_data['asm'][:2500]}\n```"
                    
                    func_data['function_summary'] = llm_interface.generate(prompt)
                
                # V7: Track TypeForge status
                has_types = any(f.get('type_constraints') for f in enriched_data['functions'])
                type_str = "T" if has_types else "-"
                
                with print_lock:
                    print(f"[{stage_id}] P{idx} ({lang}) [{type_str}] ✓", flush=True)
                
                output_q.put({
                    'enriched_data': enriched_data,
                    'lang': lang,
                    'idx': idx
                })
            except Exception as e:
                with counter_lock:
                    dropped_counter['summary'] += 1
                with print_lock:
                    print(f"[{stage_id}] P{item['data'].get('index', '?')} exception: {e} (dropped)", flush=True)
            finally:
                input_q.task_done()
    
    return worker


def _pipeline_vexhelix_stage_v7(
    input_q: Queue, 
    results: List,
    results_lock: threading.Lock,
    counters: Dict,
    total_tasks: int,
    stage_id: str = "VEXHELIX"
):
    """Pipeline Stage 4: VexHelix semantic repair loop (V7: with TypeForge constraints)."""
    def worker():
        while True:
            item = input_q.get()
            if item is PIPELINE_DONE:
                input_q.task_done()
                break
            
            try:
                enriched_data = item['enriched_data']
                lang = item['lang']
                idx = item['idx']
                task_id = f"P{idx}"
                
                # V7: Check if TypeForge constraints available
                has_types = any(f.get('type_constraints') for f in enriched_data['functions'])
                type_str = "T" if has_types else "-"
                
                with print_lock:
                    counters['active'] += 1
                    print(f"[{stage_id}] {task_id} ({lang}) [{type_str}] START | active: {counters['active']}", flush=True)
                
                start_time = time.time()
                
                # V7: Run VexHelix optimization loop with TypeForge constraints
                for func_data in enriched_data['functions']:
                    # V7: Get optimization level from data
                    opt_level = enriched_data.get('opt', 'O0')
                    
                    # V7.2: Get LLM-as-judge signature analysis
                    sig_analysis = func_data.get('signature_analysis', '')
                    
                    optimization_success, optimized_code, stats = get_optimized_code_v7(
                        c_code=func_data['ghidra_code'],
                        function_summary=func_data['function_summary'],
                        caller_and_callee_summary=gen_context_summary(enriched_data['callgraph']),
                        function_sog="",
                        type_constraints=func_data.get('type_constraints', {}),
                        language=lang,
                        llm_interface=llm_interface,
                        original_binary_path=Path(enriched_data['original_binary_path']),
                        function_name=func_data['f_name'],
                        original_asm=func_data.get('asm', ''),
                        original_ghidra=func_data['ghidra_code'],
                        opt=opt_level,
                        num_args=3,
                        task_id=task_id,
                        signature_analysis=sig_analysis  # V7.2: LLM-as-judge result
                    )
                    
                    func_data['optimization_status'] = optimization_success
                    func_data['optimized_code'] = optimized_code
                    func_data['optimization_stats'] = stats
                
                duration = time.time() - start_time
                final_result = enriched_data['functions'][0].get('optimization_stats', {}).get('final_result', 'unknown') if enriched_data['functions'] else 'no_functions'
                
                # Store result
                with results_lock:
                    results.append(enriched_data)
                
                with print_lock:
                    counters['active'] -= 1
                    counters['completed'] += 1
                    sym = "✓" if final_result == 'equivalent' else "✗"
                    stats = enriched_data['functions'][0].get('optimization_stats', {}) if enriched_data['functions'] else {}
                    print(f"[{sym}] {task_id} ({lang}) [{type_str}]: {final_result} "
                          f"({stats.get('semantic_repair_iterations', 0)}it, "
                          f"{stats.get('vexhelix_calls', 0)}vex, {duration:.1f}s) | "
                          f"done: {counters['completed']}/{total_tasks}, active: {counters['active']}", flush=True)
                
            except Exception as e:
                with print_lock:
                    counters['active'] -= 1
                    counters['completed'] += 1
                    print(f"[✗] P{item.get('idx', '?')} exception: {str(e)[:100]} | "
                          f"done: {counters['completed']}/{total_tasks}", flush=True)
            finally:
                input_q.task_done()
    
    return worker


def process_batch_pipelined_v7(batch_items: List[Dict], temp_base_dir: Path) -> List[Dict]:
    """
    Process a batch using TRUE PIPELINED ARCHITECTURE (V7).
    
    Like a CPU pipeline:
    - Stage 1 (COMPILE):  width=20, fast
    - Stage 2 (GHIDRA):   width=12, memory-heavy  
    - Stage 3 (SUMMARY):  width=12, LLM I/O bound (rate limited)
    - Stage 4 (VEXHELIX): width=12, verification (rate limited)
    
    V7 Enhancements:
    - TypeForge constraints loaded during enrichment
    - Global rate limiter enforces LLM request limits
    - Better C++ support with cxxfilt demangling
    """
    total = len(batch_items)
    
    print(f"\n{'='*70}")
    print(f"[PIPELINED V7] TRUE CPU-STYLE PIPELINE with TypeForge + VexHelix")
    print(f"{'='*70}")
    print(f"  Total programs: {total}")
    print(f"  Stage widths:")
    print(f"    COMPILE:  {PIPELINE_COMPILE_WIDTH} workers")
    print(f"    GHIDRA:   {PIPELINE_GHIDRA_WIDTH} workers")
    print(f"    SUMMARY:  {PIPELINE_SUMMARY_WIDTH} workers (LLM)")
    print(f"    VEXHELIX: {PIPELINE_VEXHELIX_WIDTH} workers (LLM)")
    print(f"  Rate Limit: {GLOBAL_RATE_LIMITER.max_rpm} LLM requests/min")
    print(f"{'='*70}\n")
    
    # Pre-resolve script paths
    cfg_script = Path(__file__).resolve().parent.parent / "src" / "scripts" / "batched_cfg_extractor.py"
    callgraph_script = Path(__file__).resolve().parent.parent / "src" / "scripts" / "batched_call_graph_extractor.py"
    
    # Create inter-stage queues
    compile_q = Queue()    # Input to compile stage
    ghidra_q = Queue()     # compile → ghidra
    summary_q = Queue()    # ghidra → summary
    vexhelix_q = Queue()   # summary → vexhelix
    
    # Results storage (thread-safe)
    results = []
    results_lock = threading.Lock()
    counters = {'active': 0, 'completed': 0}
    
    # Dropped items counter
    dropped_counter = {'compile': 0, 'ghidra': 0, 'summary': 0}
    counter_lock = threading.Lock()
    
    # Start stage workers
    all_threads = []
    
    # Stage 1: Compile workers
    for _ in range(PIPELINE_COMPILE_WIDTH):
        worker_fn = _pipeline_compile_stage_v7(compile_q, ghidra_q, temp_base_dir, dropped_counter, counter_lock)
        t = threading.Thread(target=worker_fn, daemon=True)
        t.start()
        all_threads.append(('compile', t))
    
    # Stage 2: Ghidra workers
    for _ in range(PIPELINE_GHIDRA_WIDTH):
        worker_fn = _pipeline_ghidra_stage_v7(ghidra_q, summary_q, cfg_script, callgraph_script, dropped_counter, counter_lock)
        t = threading.Thread(target=worker_fn, daemon=True)
        t.start()
        all_threads.append(('ghidra', t))
    
    # Stage 3: Summary workers
    for _ in range(PIPELINE_SUMMARY_WIDTH):
        worker_fn = _pipeline_summary_stage_v7(summary_q, vexhelix_q, dropped_counter, counter_lock)
        t = threading.Thread(target=worker_fn, daemon=True)
        t.start()
        all_threads.append(('summary', t))
    
    # Stage 4: VexHelix workers
    for _ in range(PIPELINE_VEXHELIX_WIDTH):
        worker_fn = _pipeline_vexhelix_stage_v7(vexhelix_q, results, results_lock, counters, total)
        t = threading.Thread(target=worker_fn, daemon=True)
        t.start()
        all_threads.append(('vexhelix', t))
    
    # Feed all items into the compile stage
    for item in batch_items:
        compile_q.put(item)
    
    # Wait for compile stage to drain, then signal shutdown
    compile_q.join()
    for _ in range(PIPELINE_COMPILE_WIDTH):
        compile_q.put(PIPELINE_DONE)
    
    # Wait for ghidra stage to drain, then signal shutdown
    ghidra_q.join()
    for _ in range(PIPELINE_GHIDRA_WIDTH):
        ghidra_q.put(PIPELINE_DONE)
    
    # Wait for summary stage to drain, then signal shutdown
    summary_q.join()
    for _ in range(PIPELINE_SUMMARY_WIDTH):
        summary_q.put(PIPELINE_DONE)
    
    # Wait for vexhelix stage to drain, then signal shutdown
    vexhelix_q.join()
    for _ in range(PIPELINE_VEXHELIX_WIDTH):
        vexhelix_q.put(PIPELINE_DONE)
    
    # Wait for all threads to finish
    for stage_name, t in all_threads:
        t.join(timeout=5.0)
    
    # Print summary with rate limiter stats
    total_dropped = dropped_counter['compile'] + dropped_counter['ghidra'] + dropped_counter['summary']
    equivalent_count = sum(1 for r in results 
                          if r['functions'] and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    
    c_results = [r for r in results if r.get('language') == 'c']
    cpp_results = [r for r in results if r.get('language') == 'cpp']
    c_equiv = sum(1 for r in c_results 
                  if r['functions'] and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    cpp_equiv = sum(1 for r in cpp_results 
                    if r['functions'] and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    
    # V7: TypeForge impact
    with_types = sum(1 for r in results 
                     if r['functions'] and any(f.get('type_constraints') for f in r['functions']))
    with_types_equiv = sum(1 for r in results 
                          if r['functions'] 
                          and any(f.get('type_constraints') for f in r['functions'])
                          and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    
    # V7: Rate limiter stats
    rl_stats = GLOBAL_RATE_LIMITER.get_stats()
    
    print(f"\n{'='*70}")
    print(f"[PIPELINED V7] Complete!")
    print(f"{'='*70}")
    print(f"  Processed: {len(results)}/{total}")
    if total_dropped > 0:
        print(f"  Dropped: {total_dropped} (compile:{dropped_counter['compile']}, ghidra:{dropped_counter['ghidra']}, summary:{dropped_counter['summary']})")
    print(f"  Equivalent: {equivalent_count}/{len(results)} ({100*equivalent_count/len(results) if results else 0:.0f}%)")
    print(f"    C:   {c_equiv}/{len(c_results)}")
    print(f"    C++: {cpp_equiv}/{len(cpp_results)}")
    print(f"  TypeForge Impact:")
    print(f"    With TypeForge: {with_types_equiv}/{with_types} equiv")
    print(f"    Without TypeForge: {equivalent_count - with_types_equiv}/{len(results) - with_types} equiv")
    print(f"  LLM Rate Limiter:")
    print(f"    Total requests: {rl_stats['total_requests']}")
    print(f"    Total wait time: {rl_stats['total_wait_time_seconds']}s")
    print(f"{'='*70}\n")
    
    return results


# =============================================================================
# MAIN PROCESSING PIPELINE (V7)
# =============================================================================

def process_batch(batch_items: List[Dict], temp_base_dir: Path) -> List[Dict]:
    """
    Process a batch of items through the V7 pipeline.
    
    NOW USES TRUE PIPELINED ARCHITECTURE for maximum throughput.
    """
    # V7: Use true pipelined architecture for maximum throughput
    return process_batch_pipelined_v7(batch_items, temp_base_dir)


def save_results(results: List[Dict], output_file_path: Path):
    """Save results incrementally to JSON file."""
    if output_file_path.exists():
        with open(output_file_path, "r") as f:
            existing_data = json.load(f)
        existing_data.extend(results)
        with open(output_file_path, "w") as f:
            json.dump(existing_data, f, indent=4)
    else:
        with open(output_file_path, "w") as f:
            json.dump(results, f, indent=4)


def process_humaneval_decompile(json_path: Path, start_index: int = 0, limit: int = None) -> List[Dict]:
    """
    Process the humaneval decompile json file with V7 pipeline.
    
    V7 improvements:
    - TypeForge type constraints integrated
    - Enhanced prompts for type-aware repair
    - Better synergy between VexHelix and TypeForge
    """
    output_file_path = output_dir / "batched_enriched_humaneval_decompile_v7.json"
    output_file_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(json_path, "r") as f:
        humaneval_data = json.load(f)
    
    # Apply start_index and limit
    if limit:
        humaneval_data = humaneval_data[start_index:start_index + limit]
    else:
        humaneval_data = humaneval_data[start_index:]
    
    # Add index to each item
    for i, item in enumerate(humaneval_data):
        item['index'] = start_index + i
    
    # Count languages
    c_count = sum(1 for d in humaneval_data if d['language'] == 'c')
    cpp_count = sum(1 for d in humaneval_data if d['language'] == 'cpp')
    
    print(f"\n{'='*70}")
    print(f"MissionDecompile V7 - TypeForge + VexHelix Integration")
    print(f"{'='*70}")
    print(f"Processing {len(humaneval_data)} functions")
    print(f"  - C programs: {c_count}")
    print(f"  - C++ programs: {cpp_count}")
    print(f"VexHelix API: {VEXHELIX_API_URL}")
    print(f"TypeForge path: {corpus_path / 'typeforge'}")
    print(f"{'='*70}\n")
    
    with tempfile.TemporaryDirectory() as temp_base_dir:
        temp_base_path = Path(temp_base_dir)
        
        batch_size = COMPILATION_BATCH_SIZE
        total_batches = (len(humaneval_data) + batch_size - 1) // batch_size
        
        for batch_idx in range(0, len(humaneval_data), batch_size):
            batch_num = batch_idx // batch_size + 1
            batch_items = humaneval_data[batch_idx:batch_idx + batch_size]
            
            print(f"\n{'='*70}")
            print(f"BATCH {batch_num}/{total_batches}: Processing items {start_index + batch_idx} to {start_index + batch_idx + len(batch_items) - 1}")
            print(f"{'='*70}\n")
            
            batch_results = process_batch(batch_items, temp_base_path)
            
            if batch_results:
                save_results(batch_results, output_file_path)
                print(f"\n[Save] Saved {len(batch_results)} results from batch {batch_num}")
    
    print(f"\n{'='*70}")
    print(f"Processing complete! Results saved to {output_file_path}")
    print(f"{'='*70}\n")


def check_vexhelix_api() -> bool:
    """Check if VexHelix API is reachable and healthy."""
    try:
        response = requests.get(f"{VEXHELIX_API_URL}/health", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✓ VexHelix API is healthy at {VEXHELIX_API_URL}")
            print(f"  Version: {data.get('version', 'unknown')}")
            compilers = data.get('compilers', {})
            if compilers:
                print(f"  GCC: {'✓' if compilers.get('gcc_available') else '✗'}")
                print(f"  G++: {'✓' if compilers.get('gpp_available') else '✗'}")
            return True
        else:
            print(f"⚠ VexHelix API returned unexpected status: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"✗ Cannot connect to VexHelix API at {VEXHELIX_API_URL}")
        return False
    except Exception as e:
        print(f"✗ Error checking VexHelix API: {e}")
        return False


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="MissionDecompile V7 - TypeForge + VexHelix Integration")
    parser.add_argument("--start", type=int, default=0, help="Starting index")
    parser.add_argument("--limit", type=int, default=None, help="Maximum items to process")
    parser.add_argument("--skip-api-check", action="store_true", help="Skip VexHelix API check")
    parser.add_argument("--rate-limit", type=int, default=150, help="Max LLM requests per minute (default: 150)")
    args = parser.parse_args()
    
    # V7: Configure rate limiter
    set_global_rate_limit(args.rate_limit)
    
    json_path = corpus_path / "humaneval-decompile.json"
    
    if not json_path.exists():
        print(f"✗ Dataset not found: {json_path}")
        return
    
    # Check VexHelix API
    if not args.skip_api_check:
        if not check_vexhelix_api():
            print("\n⚠ VexHelix API is not available.")
            print("  Please start VexHelix server with:")
            print("    cd /path/to/vexhelix && python -m vexhelix.api.server")
            print("  Or use --skip-api-check to continue anyway")
            return
    
    process_humaneval_decompile(json_path, args.start, args.limit)


if __name__ == "__main__":
    main()
