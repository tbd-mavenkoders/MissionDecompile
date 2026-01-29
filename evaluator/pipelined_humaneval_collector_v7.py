#!/usr/bin/env python3
"""
MissionDecompile V7 Pipelined Collector - LOCAL MODEL VERSION
=============================================================

This is the PIPELINED version of the V7 collector, designed for LOCAL MODELS
(gpt-oss via vLLM). Key differences from batched_humaneval_collector_v7.py:

1. Uses vLLM interface instead of Gemini
2. Effectively infinite rate limit (local model = no rate limits)
3. Full streaming pipeline architecture (not sequential batches)
4. Incremental per-item saves to run_{timestamp}/func_{idx:04d}.json

Pipeline Architecture:
    COMPILE(20) → GHIDRA(12) → SUMMARY(12) → VEXHELIX(12)
    
Each stage runs concurrently with items flowing through as they complete.
"""

import json
import os
import sys
import time
import threading
import tempfile
import subprocess
import datetime
import requests
from pathlib import Path
from queue import Queue
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple, Any

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml
from utils.c_program_parser import parser
from utils.compile import compile_c
from utils.disassembler import disassemble
from utils.ghidra import run_ghidra
from utils.llm_interface import create_llm_interface, set_global_rate_limit
from src.code_repair import remove_unwanted, repair_code

# =============================================================================
# CONFIGURATION - VLLM FOR LOCAL MODEL
# =============================================================================

config_path = Path(__file__).resolve().parent.parent / "config.yaml"
with open(config_path, "r") as f:
    config = yaml.safe_load(f)

corpus_path = Path(config["humaneval"]["corpus_path"])
output_dir = Path(config["humaneval"]["output_path"])
output_dir.mkdir(parents=True, exist_ok=True)

# PIPELINED: Use vLLM interface for local model (gpt-oss)
llm_interface = create_llm_interface(
    provider=config["llm"]["vllm_provider"],
    model_name=config["llm"]["vllm_model_name"],
    base_url=config["llm"]["vllm_base_url"]
)

# VexHelix API endpoint
VEXHELIX_API_URL = "http://127.0.0.1:8001"

# =============================================================================
# PIPELINED: EFFECTIVELY INFINITE RATE LIMIT FOR LOCAL MODEL
# =============================================================================
# Local models have no rate limit - set to 100,000 RPM (effectively unlimited)
set_global_rate_limit(100000)

# Import the global rate limiter for stats
from utils.llm_interface import GLOBAL_RATE_LIMITER

# =============================================================================
# PIPELINE CONFIGURATION
# =============================================================================
PIPELINE_COMPILE_WIDTH = 20   # Fast - compilation is CPU-bound
PIPELINE_GHIDRA_WIDTH = 12    # Memory-heavy - limited by Ghidra memory
PIPELINE_SUMMARY_WIDTH = 12   # LLM I/O bound (local model = fast)
PIPELINE_VEXHELIX_WIDTH = 12  # Verification + LLM

# Pipeline sentinel
PIPELINE_DONE = object()

# Print lock for thread-safe output
print_lock = threading.Lock()

# =============================================================================
# TYPEHOON STATS TRACKING
# =============================================================================

typehoon_stats = {
    'total_checked': 0,
    'matches_found': 0,
    'constraints_used': 0,
    'time_spent_ms': 0,
    'by_opt_level': {}
}
typehoon_stats_lock = threading.Lock()


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class VexHelixResult:
    """Result from VexHelix semantic verification."""
    is_equivalent: bool
    error_count: int
    test_summary: str
    raw_response: Dict
    api_time_ms: float
    
@dataclass
class CompilationResult:
    """Result from compilation stage."""
    success: bool
    executable_path: Optional[Path]
    error_message: Optional[str]
    data: Dict
    index: int


# =============================================================================
# TYPEFORGE/TYPEHOON CONSTRAINT LOADING
# =============================================================================

def get_type_constraints(data: Dict, function_name: str = "func0") -> Dict[str, Any]:
    """
    Load type constraints from TypeForge and Typehoon for a function.
    
    V7: Primary source of ground-truth type information for repair prompts.
    """
    constraints = {
        'typeforge': None,
        'typehoon': None,
        'combined_signature': None,
        'has_constraints': False
    }
    
    index = data.get('index', data.get('task_id', 'unknown'))
    opt_level = data.get('opt', 'O0')
    language = data.get('language', 'c')
    
    # TypeForge constraints (from corpus)
    tf_constraints = _load_typeforge_constraints(index, opt_level, language)
    if tf_constraints:
        constraints['typeforge'] = tf_constraints
        constraints['has_constraints'] = True
    
    # Typehoon constraints (dynamic analysis)
    th_constraints = _load_typehoon_constraints(index, opt_level, language)
    if th_constraints:
        constraints['typehoon'] = th_constraints
        constraints['has_constraints'] = True
    
    # Combine into single signature recommendation
    if constraints['has_constraints']:
        constraints['combined_signature'] = _combine_constraints(tf_constraints, th_constraints)
    
    return constraints


def _load_typeforge_constraints(index: int, opt_level: str, language: str) -> Optional[Dict]:
    """Load TypeForge constraints from corpus."""
    typeforge_path = corpus_path / "typeforge"
    
    if not typeforge_path.exists():
        return None
    
    # Try different file naming conventions
    for pattern in [
        f"{index}_{opt_level}_{language}.json",
        f"{index}_{opt_level}.json",
        f"{index}.json"
    ]:
        json_file = typeforge_path / pattern
        if json_file.exists():
            try:
                with open(json_file, 'r') as f:
                    return json.load(f)
            except Exception:
                continue
    
    return None


def _load_typehoon_constraints(index: int, opt_level: str, language: str) -> Optional[Dict]:
    """Load Typehoon constraints if available."""
    typehoon_path = corpus_path / "typehoon"
    
    if not typehoon_path.exists():
        return None
    
    start_time = time.time()
    
    for pattern in [
        f"{index}_{opt_level}_{language}.json",
        f"{index}_{opt_level}.json",
        f"{index}.json"
    ]:
        json_file = typehoon_path / pattern
        if json_file.exists():
            try:
                with open(json_file, 'r') as f:
                    constraints = json.load(f)
                
                elapsed_ms = (time.time() - start_time) * 1000
                with typehoon_stats_lock:
                    typehoon_stats['total_checked'] += 1
                    typehoon_stats['matches_found'] += 1
                    typehoon_stats['time_spent_ms'] += elapsed_ms
                    
                    if opt_level not in typehoon_stats['by_opt_level']:
                        typehoon_stats['by_opt_level'][opt_level] = {'checked': 0, 'found': 0}
                    typehoon_stats['by_opt_level'][opt_level]['checked'] += 1
                    typehoon_stats['by_opt_level'][opt_level]['found'] += 1
                
                return constraints
            except Exception:
                continue
    
    with typehoon_stats_lock:
        typehoon_stats['total_checked'] += 1
        if opt_level not in typehoon_stats['by_opt_level']:
            typehoon_stats['by_opt_level'][opt_level] = {'checked': 0, 'found': 0}
        typehoon_stats['by_opt_level'][opt_level]['checked'] += 1
    
    return None


def _combine_constraints(tf: Optional[Dict], th: Optional[Dict]) -> str:
    """Combine TypeForge and Typehoon constraints into signature recommendation."""
    parts = []
    
    if tf:
        if 'return_type' in tf:
            parts.append(f"Return type: {tf['return_type']}")
        if 'parameters' in tf:
            params = tf['parameters']
            if isinstance(params, list):
                param_str = ', '.join(f"{p.get('type', '?')} {p.get('name', f'arg{i}')}" 
                                     for i, p in enumerate(params))
                parts.append(f"Parameters: ({param_str})")
    
    if th:
        if 'inferred_signature' in th:
            parts.append(f"Typehoon suggests: {th['inferred_signature']}")
        if 'value_ranges' in th:
            parts.append(f"Value ranges: {th['value_ranges']}")
    
    return ' | '.join(parts) if parts else None


def format_type_constraints_for_prompt(constraints: Dict) -> str:
    """Format type constraints for inclusion in LLM prompt."""
    if not constraints or not constraints.get('has_constraints'):
        return ""
    
    lines = ["\n═══════════════════════════════════════════════════════════════════════════════"]
    lines.append("TYPE CONSTRAINTS (from static analysis)")
    lines.append("═══════════════════════════════════════════════════════════════════════════════")
    
    if constraints.get('combined_signature'):
        lines.append(f"\nRecommended signature: {constraints['combined_signature']}")
    
    tf = constraints.get('typeforge')
    if tf:
        lines.append("\n[TypeForge Analysis]")
        if 'return_type' in tf:
            lines.append(f"  Return type: {tf['return_type']}")
        if 'parameters' in tf:
            lines.append(f"  Parameters: {tf['parameters']}")
        if 'local_variables' in tf:
            lines.append(f"  Local variables: {tf['local_variables'][:500]}")
    
    th = constraints.get('typehoon')
    if th:
        lines.append("\n[Typehoon Dynamic Analysis]")
        for key, value in th.items():
            if key not in ['raw_data']:
                lines.append(f"  {key}: {str(value)[:200]}")
    
    lines.append("═══════════════════════════════════════════════════════════════════════════════\n")
    
    return '\n'.join(lines)


# =============================================================================
# VEXHELIX API INTEGRATION
# =============================================================================

def check_vexhelix_health() -> bool:
    """Check if VexHelix API is available."""
    try:
        response = requests.get(f"{VEXHELIX_API_URL}/health", timeout=5)
        return response.status_code == 200
    except:
        return False


def call_vexhelix_api(
    original_source: str,
    recompiled_source: str,
    language: str = "c",
    opt: str = "O0",
    function_name: str = "func0",
    num_test_inputs: int = 3,
    original_binary_path: Optional[Path] = None,
    timeout: int = 60
) -> VexHelixResult:
    """
    Call VexHelix API for semantic verification.
    
    Returns VexHelixResult with equivalence status and error count.
    """
    start_time = time.time()
    
    payload = {
        "original_source": original_source,
        "recompiled_source": recompiled_source,
        "language": language,
        "optimization_level": opt,
        "function_name": function_name,
        "num_test_inputs": num_test_inputs
    }
    
    if original_binary_path:
        payload["original_binary_path"] = str(original_binary_path)
    
    try:
        response = requests.post(
            f"{VEXHELIX_API_URL}/verify",
            json=payload,
            timeout=timeout
        )
        api_time_ms = (time.time() - start_time) * 1000
        
        if response.status_code == 200:
            data = response.json()
            return VexHelixResult(
                is_equivalent=data.get('equivalent', False),
                error_count=data.get('error_count', 1000),
                test_summary=data.get('test_summary', ''),
                raw_response=data,
                api_time_ms=api_time_ms
            )
        else:
            return VexHelixResult(
                is_equivalent=False,
                error_count=1000,  # High error count for API failures
                test_summary=f"API error: {response.status_code}",
                raw_response={'error': response.text},
                api_time_ms=api_time_ms
            )
    except requests.exceptions.Timeout:
        return VexHelixResult(
            is_equivalent=False,
            error_count=1000,
            test_summary="API timeout",
            raw_response={'error': 'timeout'},
            api_time_ms=(time.time() - start_time) * 1000
        )
    except Exception as e:
        return VexHelixResult(
            is_equivalent=False,
            error_count=1000,
            test_summary=f"API exception: {str(e)}",
            raw_response={'error': str(e)},
            api_time_ms=(time.time() - start_time) * 1000
        )


# =============================================================================
# PROMPT GENERATION
# =============================================================================

def get_initial_prompt(
    c_code: str,
    function_summary: str,
    caller_and_callee_summary: str,
    function_sog: str,
    type_constraints: Dict = None,
    language: str = 'c',
    original_asm: str = ''
) -> str:
    """Generate initial optimization prompt with TypeForge constraints."""
    
    prompt = f"""Reconstruct this decompiled code into compilable {language.upper()} source:

═══════════════════════════════════════════════════════════════════════════════
DECOMPILED CODE (may have errors - use as starting point only)
═══════════════════════════════════════════════════════════════════════════════
```{language}
{c_code}
```
"""

    if type_constraints and type_constraints.get('has_constraints'):
        prompt += format_type_constraints_for_prompt(type_constraints)
    
    if function_summary:
        prompt += f"""
═══════════════════════════════════════════════════════════════════════════════
FUNCTION ANALYSIS
═══════════════════════════════════════════════════════════════════════════════
{function_summary}
"""

    if original_asm:
        prompt += f"""
═══════════════════════════════════════════════════════════════════════════════
ASSEMBLY (GROUND TRUTH - check return registers before RET!)
═══════════════════════════════════════════════════════════════════════════════
```asm
{original_asm[:2500]}
```
"""

    prompt += """
═══════════════════════════════════════════════════════════════════════════════
REQUIREMENTS
═══════════════════════════════════════════════════════════════════════════════
1. Use EXACT signature from type constraints if provided
2. Check assembly for actual return type (xmm0=float, eax=int, void=no return reg)
3. Include all necessary headers
4. Preserve original algorithm semantics

Output ONLY the complete, compilable code. No explanations."""

    return prompt


def get_static_repair_prompt(
    original_code: str,
    error_message: str,
    c_code: str,
    type_constraints: Dict = None,
    language: str = 'c',
    original_asm: str = ''
) -> str:
    """Generate prompt for fixing compilation errors."""
    
    prompt = f"""Fix these compilation errors in the {language.upper()} code:

═══════════════════════════════════════════════════════════════════════════════
COMPILATION ERROR
═══════════════════════════════════════════════════════════════════════════════
{error_message[:2000]}

═══════════════════════════════════════════════════════════════════════════════
CURRENT CODE (has errors)
═══════════════════════════════════════════════════════════════════════════════
```{language}
{original_code}
```
"""

    if type_constraints and type_constraints.get('has_constraints'):
        prompt += format_type_constraints_for_prompt(type_constraints)
    
    if original_asm:
        prompt += f"""
═══════════════════════════════════════════════════════════════════════════════
ASSEMBLY REFERENCE
═══════════════════════════════════════════════════════════════════════════════
```asm
{original_asm[:1500]}
```
"""

    prompt += """
Fix ALL errors. Output ONLY the corrected, compilable code. No explanations."""

    return prompt


def get_semantic_repair_prompt(
    current_code: str,
    vexhelix_result: VexHelixResult,
    c_code: str,
    type_constraints: Dict = None,
    language: str = 'c',
    original_asm: str = '',
    iteration: int = 1,
    signature_analysis: str = ''
) -> str:
    """Generate prompt for fixing semantic mismatches found by VexHelix."""
    
    prompt = f"""Fix semantic mismatch (iteration {iteration}):

═══════════════════════════════════════════════════════════════════════════════
VEXHELIX TEST RESULTS
═══════════════════════════════════════════════════════════════════════════════
Error count: {vexhelix_result.error_count}
{vexhelix_result.test_summary[:1500]}

═══════════════════════════════════════════════════════════════════════════════
CURRENT CODE (compiles but wrong behavior)
═══════════════════════════════════════════════════════════════════════════════
```{language}
{current_code}
```

═══════════════════════════════════════════════════════════════════════════════
ORIGINAL DECOMPILED CODE
═══════════════════════════════════════════════════════════════════════════════
```{language}
{c_code}
```
"""

    if signature_analysis:
        prompt += f"""
═══════════════════════════════════════════════════════════════════════════════
SIGNATURE ANALYSIS (LLM-as-judge from assembly)
═══════════════════════════════════════════════════════════════════════════════
{signature_analysis}
"""

    if type_constraints and type_constraints.get('has_constraints'):
        prompt += format_type_constraints_for_prompt(type_constraints)
    
    if original_asm:
        prompt += f"""
═══════════════════════════════════════════════════════════════════════════════
ASSEMBLY (GROUND TRUTH)
═══════════════════════════════════════════════════════════════════════════════
```asm
{original_asm[:2000]}
```
"""

    prompt += """
═══════════════════════════════════════════════════════════════════════════════
REPAIR STRATEGY
═══════════════════════════════════════════════════════════════════════════════
1. Analyze test failures to identify the bug
2. Check if return type matches assembly (xmm0=float, eax=int)
3. Verify algorithm produces correct output
4. Match type constraints exactly

Output ONLY the corrected code. No explanations."""

    return prompt


# =============================================================================
# COMPILATION AND ANALYSIS UTILITIES
# =============================================================================

def compile_code(source_code: str, output_path: Path, language: str = 'c', opt: str = 'O0') -> Tuple[bool, str]:
    """Compile source code and return (success, error_message)."""
    ext = '.cpp' if language == 'cpp' else '.c'
    source_file = output_path.with_suffix(ext)
    
    try:
        with open(source_file, 'w') as f:
            f.write(source_code)
        
        compiler = 'g++' if language == 'cpp' else 'gcc'
        cmd = [compiler, f'-{opt}', '-o', str(output_path), str(source_file)]
        
        if language == 'cpp':
            cmd.insert(1, '-std=c++17')
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            return True, ""
        else:
            return False, result.stderr
            
    except subprocess.TimeoutExpired:
        return False, "Compilation timeout"
    except Exception as e:
        return False, str(e)


def compile_single_program(data: Dict, temp_dir: Path) -> CompilationResult:
    """Compile a single program from humaneval data."""
    index = data.get('index', 0)
    code = data.get('c_func', data.get('code', ''))
    language = data.get('language', 'c')
    opt = data.get('opt', 'O0')
    
    if not code:
        return CompilationResult(
            success=False,
            executable_path=None,
            error_message="No source code",
            data=data,
            index=index
        )
    
    # Add headers if needed
    if language == 'cpp':
        headers = "#include <vector>\n#include <string>\n#include <algorithm>\n#include <cmath>\nusing namespace std;\n\n"
        if not code.startswith('#include'):
            code = headers + code
    else:
        headers = "#include <stdlib.h>\n#include <math.h>\n#include <string.h>\n\n"
        if not code.startswith('#include'):
            code = headers + code
    
    output_path = temp_dir / f"prog_{index}"
    success, error = compile_code(code, output_path, language, opt)
    
    return CompilationResult(
        success=success,
        executable_path=output_path if success else None,
        error_message=error if not success else None,
        data=data,
        index=index
    )


def batch_compile_programs(batch: List[Dict], temp_dir: Path) -> List[CompilationResult]:
    """Compile a batch of programs in parallel."""
    results = []
    with ThreadPoolExecutor(max_workers=PIPELINE_COMPILE_WIDTH) as executor:
        futures = {executor.submit(compile_single_program, data, temp_dir): data for data in batch}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                data = futures[future]
                results.append(CompilationResult(
                    success=False,
                    executable_path=None,
                    error_message=str(e),
                    data=data,
                    index=data.get('index', 0)
                ))
    return results


def batch_ghidra_analysis(exe_list: List[Tuple[int, Path]]) -> Dict[int, Dict]:
    """Run Ghidra analysis on a batch of executables."""
    results = {}
    
    cfg_script = Path(__file__).resolve().parent.parent / "src" / "scripts" / "batched_cfg_extractor.py"
    callgraph_script = Path(__file__).resolve().parent.parent / "src" / "scripts" / "batched_call_graph_extractor.py"
    
    def analyze_one(args):
        idx, exe_path = args
        try:
            cfg_result = run_ghidra(str(exe_path), cfg_script)
            cg_result = run_ghidra(str(exe_path), callgraph_script)
            return idx, {'cfg': cfg_result, 'callgraph': cg_result}
        except Exception as e:
            return idx, {'error': str(e)}
    
    with ThreadPoolExecutor(max_workers=PIPELINE_GHIDRA_WIDTH) as executor:
        futures = [executor.submit(analyze_one, args) for args in exe_list]
        for future in as_completed(futures):
            try:
                idx, result = future.result()
                results[idx] = result
            except Exception:
                pass
    
    return results


def analyze_single_executable(exe_path: Path, cfg_script: Path, callgraph_script: Path) -> Dict:
    """Run CFG and callgraph extraction on a single executable."""
    try:
        cfg_result = run_ghidra(str(exe_path), cfg_script)
        cg_result = run_ghidra(str(exe_path), callgraph_script)
        return {'cfg': cfg_result, 'callgraph': cg_result, 'error': None}
    except Exception as e:
        return {'cfg': None, 'callgraph': None, 'error': str(e)}


def gen_code_summary_batch(functions_data: List[Dict]) -> List[Dict]:
    """Generate summaries for a batch of functions."""
    for func_data in functions_data:
        if 'ghidra_code' not in func_data:
            continue
        
        prompt = f"""Analyze this decompiled function and provide:
1. What the function does
2. Expected return type (based on operations)
3. Parameter types and purposes

```c
{func_data['ghidra_code'][:3000]}
```

Be concise. Focus on semantics, not syntax."""

        try:
            func_data['function_summary'] = llm_interface.generate(prompt)
        except Exception as e:
            func_data['function_summary'] = f"Summary generation failed: {e}"
    
    return functions_data


def gen_context_summary(callgraph: Dict) -> str:
    """Generate context summary from callgraph."""
    if not callgraph:
        return ""
    
    callers = callgraph.get('callers', [])
    callees = callgraph.get('callees', [])
    
    summary_parts = []
    if callers:
        summary_parts.append(f"Called by: {', '.join(callers[:5])}")
    if callees:
        summary_parts.append(f"Calls: {', '.join(callees[:5])}")
    
    return ' | '.join(summary_parts)


# =============================================================================
# MAIN OPTIMIZATION LOOP (V7 with VexHelix)
# =============================================================================

MAX_STATIC_REPAIR_ITERATIONS = 3
MAX_SEMANTIC_REPAIR_ITERATIONS = 5

def get_optimized_code_v7(
    c_code: str,
    function_summary: str,
    caller_and_callee_summary: str,
    function_sog: str,
    type_constraints: Dict,
    language: str,
    llm_interface,
    original_binary_path: Path,
    function_name: str = "func0",
    original_asm: str = "",
    original_ghidra: str = "",
    opt: str = "O0",
    num_args: int = 3,
    task_id: str = "",
    signature_analysis: str = ""
) -> Tuple[bool, str, Dict]:
    """
    Main optimization loop with VexHelix semantic verification.
    
    V7 Flow:
    1. Generate initial code with type constraints
    2. Static repair loop until it compiles
    3. Semantic repair loop using VexHelix feedback
    4. Return best code found
    
    Returns:
        (success, optimized_code, stats_dict)
    """
    stats = {
        'static_repair_iterations': 0,
        'semantic_repair_iterations': 0,
        'vexhelix_calls': 0,
        'final_result': 'unknown',
        'best_error_count': float('inf'),
        'type_constraints_used': bool(type_constraints and type_constraints.get('has_constraints'))
    }
    
    # Step 1: Generate initial code
    initial_prompt = get_initial_prompt(
        c_code=c_code,
        function_summary=function_summary,
        caller_and_callee_summary=caller_and_callee_summary,
        function_sog=function_sog,
        type_constraints=type_constraints,
        language=language,
        original_asm=original_asm
    )
    
    current_code = llm_interface.generate(initial_prompt)
    current_code = repair_code(current_code, language)
    
    # Step 2: Static repair loop
    best_code = current_code
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        exe_path = temp_path / "test_exe"
        
        for i in range(MAX_STATIC_REPAIR_ITERATIONS):
            success, error = compile_code(current_code, exe_path, language, opt)
            
            if success:
                break
            
            stats['static_repair_iterations'] += 1
            
            repair_prompt = get_static_repair_prompt(
                original_code=current_code,
                error_message=error,
                c_code=c_code,
                type_constraints=type_constraints,
                language=language,
                original_asm=original_asm
            )
            
            current_code = llm_interface.generate(repair_prompt)
            current_code = repair_code(current_code, language)
        
        # Final compilation check
        success, error = compile_code(current_code, exe_path, language, opt)
        
        if not success:
            stats['final_result'] = 'compile_fail'
            return False, best_code, stats
        
        # Step 3: Semantic repair loop with VexHelix
        original_source = c_code
        
        for i in range(MAX_SEMANTIC_REPAIR_ITERATIONS):
            stats['vexhelix_calls'] += 1
            
            vex_result = call_vexhelix_api(
                original_source=original_source,
                recompiled_source=current_code,
                language=language,
                opt=opt,
                function_name=function_name,
                original_binary_path=original_binary_path
            )
            
            # Track best result
            if vex_result.error_count < stats['best_error_count']:
                stats['best_error_count'] = vex_result.error_count
                best_code = current_code
            
            if vex_result.is_equivalent:
                stats['final_result'] = 'equivalent'
                return True, current_code, stats
            
            stats['semantic_repair_iterations'] += 1
            
            # Generate semantic repair prompt
            repair_prompt = get_semantic_repair_prompt(
                current_code=current_code,
                vexhelix_result=vex_result,
                c_code=c_code,
                type_constraints=type_constraints,
                language=language,
                original_asm=original_asm,
                iteration=i + 1,
                signature_analysis=signature_analysis
            )
            
            current_code = llm_interface.generate(repair_prompt)
            current_code = repair_code(current_code, language)
            
            # Recompile
            success, error = compile_code(current_code, exe_path, language, opt)
            if not success:
                current_code = best_code
        
        # Final check
        stats['vexhelix_calls'] += 1
        vex_result = call_vexhelix_api(
            original_source=original_source,
            recompiled_source=current_code,
            language=language,
            opt=opt,
            function_name=function_name,
            original_binary_path=original_binary_path
        )
        
        if vex_result.is_equivalent:
            stats['final_result'] = 'equivalent'
            return True, current_code, stats
        
        if vex_result.error_count < stats['best_error_count']:
            best_code = current_code
            stats['best_error_count'] = vex_result.error_count
        
        stats['final_result'] = 'not_equivalent'
        return False, best_code, stats


# =============================================================================
# DATA ENRICHMENT
# =============================================================================

def split_enrichment(data: Dict, ghidra_result: Dict, exe_path: Path) -> Dict:
    """
    Enrich program data with Ghidra analysis and TypeForge constraints.
    
    V7: Adds type constraints to each function.
    """
    enriched = {
        'index': data.get('index'),
        'task_id': data.get('task_id'),
        'language': data.get('language', 'c'),
        'opt': data.get('opt', 'O0'),
        'original_code': data.get('c_func', data.get('code', '')),
        'original_binary_path': str(exe_path),
        'functions': [],
        'callgraph': ghidra_result.get('callgraph', {})
    }
    
    cfg_data = ghidra_result.get('cfg', {})
    
    # Extract function data
    functions = cfg_data.get('functions', [cfg_data]) if cfg_data else [{}]
    
    for func in functions:
        func_data = {
            'f_name': func.get('name', 'func0'),
            'ghidra_code': func.get('decompiled', data.get('ghidra_code', '')),
            'asm': func.get('assembly', data.get('asm', '')),
            'type_constraints': get_type_constraints(data, func.get('name', 'func0'))
        }
        enriched['functions'].append(func_data)
    
    # Ensure at least one function
    if not enriched['functions']:
        enriched['functions'].append({
            'f_name': 'func0',
            'ghidra_code': data.get('ghidra_code', ''),
            'asm': data.get('asm', ''),
            'type_constraints': get_type_constraints(data)
        })
    
    return enriched


# =============================================================================
# PARALLEL OPTIMIZATION (BATCH)
# =============================================================================

def batch_optimize_functions_v7(enriched_programs: List[Dict]) -> List[Dict]:
    """
    Optimize functions in parallel.
    
    Uses ThreadPoolExecutor for parallel processing.
    """
    def optimize_one(enriched_data: Dict) -> Dict:
        for func_data in enriched_data.get('functions', []):
            opt_level = enriched_data.get('opt', 'O0')
            sig_analysis = func_data.get('signature_analysis', '')
            
            success, optimized_code, stats = get_optimized_code_v7(
                c_code=func_data.get('ghidra_code', ''),
                function_summary=func_data.get('function_summary', ''),
                caller_and_callee_summary=gen_context_summary(enriched_data.get('callgraph', {})),
                function_sog="",
                type_constraints=func_data.get('type_constraints', {}),
                language=enriched_data.get('language', 'c'),
                llm_interface=llm_interface,
                original_binary_path=Path(enriched_data.get('original_binary_path', '')),
                function_name=func_data.get('f_name', 'func0'),
                original_asm=func_data.get('asm', ''),
                original_ghidra=func_data.get('ghidra_code', ''),
                opt=opt_level,
                task_id=f"P{enriched_data.get('index', '?')}",
                signature_analysis=sig_analysis
            )
            
            func_data['optimization_status'] = success
            func_data['optimized_code'] = optimized_code
            func_data['optimization_stats'] = stats
        
        return enriched_data
    
    results = []
    with ThreadPoolExecutor(max_workers=PIPELINE_VEXHELIX_WIDTH) as executor:
        futures = {executor.submit(optimize_one, prog): prog for prog in enriched_programs}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                prog = futures[future]
                prog['optimization_error'] = str(e)
                results.append(prog)
    
    return results


# =============================================================================
# PIPELINE STAGE FUNCTIONS
# =============================================================================

def _pipeline_compile_stage_v7(
    input_q: Queue,
    output_q: Queue,
    temp_dir: Path,
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
                result = compile_single_program(item, temp_dir)
                
                if result.success:
                    with print_lock:
                        print(f"[{stage_id}] P{result.index} ({item.get('language', '?')}) ✓", flush=True)
                    output_q.put({
                        'compile_result': result,
                        'data': item
                    })
                else:
                    with counter_lock:
                        dropped_counter['compile'] += 1
                    with print_lock:
                        print(f"[{stage_id}] P{result.index} ✗ compile fail", flush=True)
            except Exception as e:
                with counter_lock:
                    dropped_counter['compile'] += 1
                with print_lock:
                    print(f"[{stage_id}] P{item.get('index', '?')} exception: {e}", flush=True)
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
    """Pipeline Stage 2: Run Ghidra analysis."""
    def worker():
        while True:
            item = input_q.get()
            if item is PIPELINE_DONE:
                input_q.task_done()
                break
            
            try:
                compile_result = item['compile_result']
                data = item['data']
                exe_path = compile_result.executable_path
                
                ghidra_result = analyze_single_executable(exe_path, cfg_script, callgraph_script)
                
                if ghidra_result.get('error'):
                    with counter_lock:
                        dropped_counter['ghidra'] += 1
                    with print_lock:
                        print(f"[{stage_id}] P{compile_result.index} ✗ ghidra fail", flush=True)
                else:
                    with print_lock:
                        print(f"[{stage_id}] P{compile_result.index} ✓", flush=True)
                    output_q.put({
                        'compile_result': compile_result,
                        'ghidra_result': ghidra_result,
                        'data': data
                    })
            except Exception as e:
                with counter_lock:
                    dropped_counter['ghidra'] += 1
                with print_lock:
                    print(f"[{stage_id}] P{item.get('compile_result', {}).index if hasattr(item.get('compile_result', {}), 'index') else '?'} exception: {e}", flush=True)
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
    """Pipeline Stage 3: Generate summaries with TypeForge enrichment."""
    def worker():
        while True:
            item = input_q.get()
            if item is PIPELINE_DONE:
                input_q.task_done()
                break
            
            try:
                compile_result = item['compile_result']
                ghidra_result = item['ghidra_result']
                data = item['data']
                
                idx = compile_result.index
                lang = data.get('language', 'c')
                exe_path = compile_result.executable_path
                
                # Enrich with TypeForge constraints
                enriched_data = split_enrichment(data, ghidra_result, exe_path)
                
                # Generate summaries for each function
                for func_data in enriched_data['functions']:
                    prompt = f"""Analyze this decompiled {lang} function:

```{lang}
{func_data['ghidra_code'][:3000]}
```

Provide:
1. Function purpose
2. Expected return type
3. Parameter types and purposes

Be concise."""

                    if func_data.get('asm'):
                        prompt += f"\n\nAssembly (check xmm0/eax before RET for return type):\n```asm\n{func_data['asm'][:2500]}\n```"
                    
                    func_data['function_summary'] = llm_interface.generate(prompt)
                    
                    # LLM-as-judge signature analysis
                    if func_data.get('asm'):
                        sig_prompt = f"""Analyze this assembly and determine the EXACT function signature:

```asm
{func_data['asm'][:2000]}
```

Based on:
- Return register usage (xmm0 = float/double, eax = int, no return reg = void)
- Parameter registers used
- Stack frame setup

Output format: `return_type func0(param_type1, param_type2, ...)`"""
                        
                        func_data['signature_analysis'] = llm_interface.generate(sig_prompt)
                
                # Track TypeForge status
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
    incremental_save_dir: Path,
    stage_id: str = "VEXHELIX"
):
    """Pipeline Stage 4: VexHelix semantic repair loop with incremental saves."""
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
                
                has_types = any(f.get('type_constraints') for f in enriched_data['functions'])
                type_str = "T" if has_types else "-"
                
                with print_lock:
                    counters['active'] += 1
                    print(f"[{stage_id}] {task_id} ({lang}) [{type_str}] START | active: {counters['active']}", flush=True)
                
                start_time = time.time()
                
                # Run optimization for each function
                for func_data in enriched_data['functions']:
                    opt_level = enriched_data.get('opt', 'O0')
                    sig_analysis = func_data.get('signature_analysis', '')
                    
                    success, optimized_code, stats = get_optimized_code_v7(
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
                        task_id=task_id,
                        signature_analysis=sig_analysis
                    )
                    
                    func_data['optimization_status'] = success
                    func_data['optimized_code'] = optimized_code
                    func_data['optimization_stats'] = stats
                
                duration = time.time() - start_time
                final_result = enriched_data['functions'][0].get('optimization_stats', {}).get('final_result', 'unknown') if enriched_data['functions'] else 'no_functions'
                
                # Store in memory
                with results_lock:
                    results.append(enriched_data)
                
                # INCREMENTAL SAVE - save immediately to individual file
                try:
                    incremental_file = incremental_save_dir / f"func_{idx:04d}.json"
                    with open(incremental_file, 'w') as f:
                        json.dump(enriched_data, f, indent=2)
                except Exception as save_err:
                    print(f"[SAVE] Warning: Failed to save {task_id}: {save_err}")
                
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


# =============================================================================
# MAIN PIPELINE PROCESSOR
# =============================================================================

def process_pipelined_v7(batch_items: List[Dict], temp_base_dir: Path, incremental_save_dir: Path = None) -> Tuple[List[Dict], Path]:
    """
    Process items through TRUE PIPELINED ARCHITECTURE.
    
    PIPELINED (local model) architecture:
    - Stage 1 (COMPILE):  width=20, fast
    - Stage 2 (GHIDRA):   width=12, memory-heavy
    - Stage 3 (SUMMARY):  width=12, LLM (local = fast)
    - Stage 4 (VEXHELIX): width=12, LLM + verification
    
    INCREMENTAL SAVES: Each result saved immediately to individual file.
    """
    total = len(batch_items)
    
    # Create timestamped directory for incremental saves
    if incremental_save_dir is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        incremental_save_dir = output_dir / f"run_{timestamp}"
    incremental_save_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*70}")
    print(f"[PIPELINED V7] TRUE STREAMING PIPELINE - LOCAL MODEL")
    print(f"{'='*70}")
    print(f"  Total programs: {total}")
    print(f"  Stage widths:")
    print(f"    COMPILE:  {PIPELINE_COMPILE_WIDTH} workers")
    print(f"    GHIDRA:   {PIPELINE_GHIDRA_WIDTH} workers")
    print(f"    SUMMARY:  {PIPELINE_SUMMARY_WIDTH} workers (LLM - LOCAL)")
    print(f"    VEXHELIX: {PIPELINE_VEXHELIX_WIDTH} workers (LLM - LOCAL)")
    print(f"  Rate Limit: {GLOBAL_RATE_LIMITER.max_rpm} RPM (effectively unlimited)")
    print(f"  LLM Provider: vLLM ({config['llm']['vllm_model_name']})")
    print(f"  Incremental saves: {incremental_save_dir}")
    print(f"{'='*70}\n")
    
    # Pre-resolve script paths
    cfg_script = Path(__file__).resolve().parent.parent / "src" / "scripts" / "batched_cfg_extractor.py"
    callgraph_script = Path(__file__).resolve().parent.parent / "src" / "scripts" / "batched_call_graph_extractor.py"
    
    # Create inter-stage queues
    compile_q = Queue()
    ghidra_q = Queue()
    summary_q = Queue()
    vexhelix_q = Queue()
    
    # Results storage
    results = []
    results_lock = threading.Lock()
    counters = {'active': 0, 'completed': 0}
    
    # Dropped items counter
    dropped_counter = {'compile': 0, 'ghidra': 0, 'summary': 0}
    counter_lock = threading.Lock()
    
    # Start stage workers
    all_threads = []
    
    # Stage 1: Compile
    for _ in range(PIPELINE_COMPILE_WIDTH):
        worker_fn = _pipeline_compile_stage_v7(compile_q, ghidra_q, temp_base_dir, dropped_counter, counter_lock)
        t = threading.Thread(target=worker_fn, daemon=True)
        t.start()
        all_threads.append(('compile', t))
    
    # Stage 2: Ghidra
    for _ in range(PIPELINE_GHIDRA_WIDTH):
        worker_fn = _pipeline_ghidra_stage_v7(ghidra_q, summary_q, cfg_script, callgraph_script, dropped_counter, counter_lock)
        t = threading.Thread(target=worker_fn, daemon=True)
        t.start()
        all_threads.append(('ghidra', t))
    
    # Stage 3: Summary
    for _ in range(PIPELINE_SUMMARY_WIDTH):
        worker_fn = _pipeline_summary_stage_v7(summary_q, vexhelix_q, dropped_counter, counter_lock)
        t = threading.Thread(target=worker_fn, daemon=True)
        t.start()
        all_threads.append(('summary', t))
    
    # Stage 4: VexHelix (with incremental saves)
    for _ in range(PIPELINE_VEXHELIX_WIDTH):
        worker_fn = _pipeline_vexhelix_stage_v7(vexhelix_q, results, results_lock, counters, total, incremental_save_dir)
        t = threading.Thread(target=worker_fn, daemon=True)
        t.start()
        all_threads.append(('vexhelix', t))
    
    # Feed items into pipeline
    for item in batch_items:
        compile_q.put(item)
    
    # Wait for stages to complete
    compile_q.join()
    for _ in range(PIPELINE_COMPILE_WIDTH):
        compile_q.put(PIPELINE_DONE)
    
    ghidra_q.join()
    for _ in range(PIPELINE_GHIDRA_WIDTH):
        ghidra_q.put(PIPELINE_DONE)
    
    summary_q.join()
    for _ in range(PIPELINE_SUMMARY_WIDTH):
        summary_q.put(PIPELINE_DONE)
    
    vexhelix_q.join()
    for _ in range(PIPELINE_VEXHELIX_WIDTH):
        vexhelix_q.put(PIPELINE_DONE)
    
    # Wait for threads
    for stage_name, t in all_threads:
        t.join(timeout=5.0)
    
    # Print summary
    total_dropped = dropped_counter['compile'] + dropped_counter['ghidra'] + dropped_counter['summary']
    equivalent_count = sum(1 for r in results 
                          if r['functions'] and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    
    c_results = [r for r in results if r.get('language') == 'c']
    cpp_results = [r for r in results if r.get('language') == 'cpp']
    c_equiv = sum(1 for r in c_results 
                  if r['functions'] and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    cpp_equiv = sum(1 for r in cpp_results 
                    if r['functions'] and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    
    # TypeForge impact
    with_types = sum(1 for r in results 
                     if r['functions'] and any(f.get('type_constraints') for f in r['functions']))
    with_types_equiv = sum(1 for r in results 
                          if r['functions'] 
                          and any(f.get('type_constraints') for f in r['functions'])
                          and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    
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
    print(f"  LLM Stats:")
    print(f"    Total requests: {rl_stats['total_requests']}")
    print(f"    Total wait time: {rl_stats['total_wait_time_seconds']}s")
    print(f"  Incremental saves: {incremental_save_dir}")
    print(f"{'='*70}\n")
    
    # Combine incremental files
    combined_file = incremental_save_dir / "combined_results.json"
    try:
        combined_results = []
        for json_file in sorted(incremental_save_dir.glob("func_*.json")):
            with open(json_file, 'r') as f:
                combined_results.append(json.load(f))
        
        combined_results.sort(key=lambda x: x.get('index', 0))
        
        with open(combined_file, 'w') as f:
            json.dump(combined_results, f, indent=2)
        print(f"[SAVE] Combined {len(combined_results)} results into {combined_file}")
    except Exception as e:
        print(f"[SAVE] Warning: Failed to combine results: {e}")
    
    return results, incremental_save_dir


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def process_humaneval_decompile(json_path: Path, start_index: int = 0, limit: int = None) -> List[Dict]:
    """
    Process humaneval-decompile dataset with PIPELINED architecture.
    
    PIPELINED (local model) version:
    - Full streaming pipeline (items flow through stages as they complete)
    - Effectively unlimited rate (local model)
    - Incremental saves (each result to separate file)
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    incremental_save_dir = output_dir / f"run_{timestamp}"
    incremental_save_dir.mkdir(parents=True, exist_ok=True)
    
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
    print(f"MissionDecompile V7 - PIPELINED LOCAL MODEL VERSION")
    print(f"{'='*70}")
    print(f"Processing {len(humaneval_data)} functions via STREAMING PIPELINE")
    print(f"  - C programs: {c_count}")
    print(f"  - C++ programs: {cpp_count}")
    print(f"  - Start index: {start_index}")
    print(f"LLM: vLLM @ {config['llm']['vllm_base_url']}")
    print(f"Model: {config['llm']['vllm_model_name']}")
    print(f"VexHelix API: {VEXHELIX_API_URL}")
    print(f"TypeForge path: {corpus_path / 'typeforge'}")
    print(f"Rate limit: EFFECTIVELY UNLIMITED (local model)")
    print(f"Output directory: {incremental_save_dir}")
    print(f"{'='*70}\n")
    
    with tempfile.TemporaryDirectory() as temp_base_dir:
        temp_base_path = Path(temp_base_dir)
        
        # Process ALL items through streaming pipeline
        results, save_dir = process_pipelined_v7(humaneval_data, temp_base_path, incremental_save_dir)
    
    # Final summary
    equivalent_count = sum(1 for r in results 
                          if r.get('functions') and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    
    print(f"\n{'='*70}")
    print(f"Processing complete!")
    print(f"  Total processed: {len(results)}/{len(humaneval_data)}")
    print(f"  Total equivalent: {equivalent_count}/{len(results)}")
    print(f"  Results directory: {save_dir}")
    print(f"  Combined results: {save_dir / 'combined_results.json'}")
    print(f"{'='*70}\n")
    
    return results


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
    
    parser = argparse.ArgumentParser(description="MissionDecompile V7 - PIPELINED LOCAL MODEL VERSION")
    parser.add_argument("--start", type=int, default=0, help="Starting index (default: 0)")
    parser.add_argument("--limit", type=int, default=None, help="Maximum items to process")
    parser.add_argument("--skip-api-check", action="store_true", help="Skip VexHelix API check")
    args = parser.parse_args()
    
    # Note: Rate limit already set to 100,000 (effectively unlimited) at module load
    
    json_path = corpus_path / "humaneval-decompile.json"
    
    if not json_path.exists():
        print(f"✗ Dataset not found: {json_path}")
        return
    
    # Check vLLM endpoint
    print(f"Checking vLLM endpoint at {config['llm']['vllm_base_url']}...")
    try:
        import requests
        response = requests.get(f"{config['llm']['vllm_base_url']}/health", timeout=5)
        print(f"✓ vLLM endpoint is reachable")
    except Exception as e:
        print(f"⚠ vLLM endpoint check failed: {e}")
        print("  Continuing anyway (may fail if vLLM is not running)")
    
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
