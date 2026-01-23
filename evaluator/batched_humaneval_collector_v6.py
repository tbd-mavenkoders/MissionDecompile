"""
Batched HumanEval Collector V6 - VexHelix Semantic Verification

This module extends MissionDecompile with:
- Static repair (ensure compilation)
- Semantic verification via VexHelix API (ensure logical correctness)
- Semantic repair loop when VexHelix detects divergence
- FULL C and C++ support (unlike v2)
- Concurrent static repair for 10-20 testcases at a time

Key changes from v2:
- Replaces D-Helix (KLEE-based) with VexHelix (angr VEX IR-based)
- VexHelix returns "equivalent"/"different" instead of "unsat"/"sat"
- C++ support via extern "C" handling in VexHelix
- Concurrent execution of static repair phase
- Better error handling and counterexample formatting

Pipeline:
1. Batch compilation of original code
2. Batch Ghidra analysis (CFG + call graphs)
3. Concurrent static repair loop
4. Sequential semantic verification via VexHelix
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

from utils.llm_interface import create_llm_interface, LLMInterface
from utils.compile import Compiler, OptimizationLevel
from utils.ghidra import Ghidra
from utils.clean_errors import ErrorNormalizer
from src.sort_callgraph import build_call_graph, topological_sort

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

# =============================================================================
# CONFIGURATION
# =============================================================================

# Batching configuration
COMPILATION_BATCH_SIZE = 20
GHIDRA_BATCH_SIZE = 12
LLM_BATCH_SIZE = 8

# Concurrent static repair configuration (NEW in v6)
CONCURRENT_REPAIR_SIZE = 16  # Number of testcases to repair concurrently

# VexHelix API configuration (replaces D-Helix)
VEXHELIX_API_URL = "http://127.0.0.1:8001"
VEXHELIX_TIMEOUT = 120  # seconds per verification (reduced for efficiency)
VEXHELIX_LOOP_BOUND = 5  # Maximum loop iterations in symbolic execution

# Repair configuration
MAX_REPAIR_ITERATIONS = 15  # Total iterations including static + semantic repair
MAX_STATIC_REPAIR_PER_CYCLE = 3  # Max static repair attempts before checking semantics

# Token limit configuration (GPT-OSS-20B has 130K context)
MAX_CONTEXT_TOKENS = 130_000
MAX_ERROR_CHARS = 2000  # ~500 tokens for errors
MAX_ASM_CHARS = 8000    # ~2000 tokens for assembly
MAX_CODE_CHARS = 12000  # ~3000 tokens for code


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
    
    VexHelix uses bounded relational symbolic execution with angr VEX IR.
    Unlike D-Helix (KLEE-based), it compiles the decompiled code and compares
    both binaries side-by-side.
    
    Args:
        binary_path: Path to original compiled binary
        decompiled_code: The decompiled/repaired source code
        function_name: Name of the function to verify
        language: "c" or "cpp"
        num_args: Number of function arguments (default 3)
        loop_bound: Maximum loop iterations (default 5)
    
    Returns:
        VexHelixResult with verification outcome
    """
    try:
        lang_str = "cpp" if language.lower() == "cpp" else "c"
        print(f"[VexHelix] Verifying {function_name} ({lang_str}) against binary {binary_path.name}...")
        
        with open(binary_path, 'rb') as binary_file:
            # VexHelix uses Form fields + File upload (not JSON body)
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
                timeout=VEXHELIX_TIMEOUT + 30  # Extra buffer for network
            )
        
        if response.status_code == 200:
            result = response.json()
            status = result.get('status', 'error')
            equivalent = result.get('equivalent', None)
            
            # Map VexHelix status to our result
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
            error_msg = f"HTTP {response.status_code}: {response.text[:500]}"
            print(f"[VexHelix] Error: {error_msg}")
            return VexHelixResult(
                success=False,
                status='error',
                equivalent=None,
                divergences=None,
                statistics=None,
                error_message=error_msg,
                compilation_error=None
            )
    
    except requests.exceptions.Timeout:
        print(f"[VexHelix] Timeout after {VEXHELIX_TIMEOUT}s")
        return VexHelixResult(
            success=False,
            status='timeout',
            equivalent=None,
            divergences=None,
            statistics=None,
            error_message=f"Request timeout after {VEXHELIX_TIMEOUT}s",
            compilation_error=None
        )
    except Exception as e:
        print(f"[VexHelix] Exception: {e}")
        return VexHelixResult(
            success=False,
            status='error',
            equivalent=None,
            divergences=None,
            statistics=None,
            error_message=str(e),
            compilation_error=None
        )


# =============================================================================
# PROMPT GENERATION
# =============================================================================

def get_initial_prompt(c_code: str, function_summary: str, caller_and_callee_summary: str, 
                      function_sog: str, language: str) -> str:
    """Generate the initial prompt for the repair tool."""
    initial_prompt = config["prompts"]["system_prompt"]
    prompt = f"{initial_prompt}\n\n```Language:{language}\nSummary:{function_summary}\n{c_code}\n```"
    if caller_and_callee_summary:
        prompt += f"\n\nCaller and Callee Summary:\n{caller_and_callee_summary}"
    if function_sog:
        prompt += f"\n\nFunction SOG:\n{function_sog}"
    return prompt


def get_static_repair_prompt(c_code: str, compilation_errors: str, function_summary: str,
                            caller_and_callee_summary: str, function_sog: str, language: str) -> str:
    """Generate the static repair prompt for compilation errors."""
    repair_prompt = config["prompts"]["compilation_error"]
    lang_label = "cpp" if language == "cpp" else "c"
    # Truncate errors to stay within token limits
    truncated_errors = compilation_errors[:MAX_ERROR_CHARS]
    if len(compilation_errors) > MAX_ERROR_CHARS:
        truncated_errors += "\n... (error truncated)"
    truncated_code = c_code[:MAX_CODE_CHARS]
    if len(c_code) > MAX_CODE_CHARS:
        truncated_code += "\n// ... (code truncated)"
    prompt = f"{repair_prompt}\n\n```{lang_label}\nLanguage:{language}\nSummary:{function_summary}\nCode:{truncated_code}\n```\n\nCompilation Errors:\n{truncated_errors}\n\nPlease provide the corrected {language.upper()} code."
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
    language: str
) -> str:
    """
    Generate semantic repair prompt using VexHelix verification results.
    
    VexHelix provides:
    - Divergence information with concrete counterexample inputs
    - Execution statistics
    """
    semantic_prompt = config["prompts"]["semantic_repair"]
    
    prompt = f"{semantic_prompt}\n\n"
    
    # Add context
    prompt += f"Language: {language.upper()}\n\n"
    
    # Truncate assembly to stay within token limits
    truncated_asm = original_asm[:MAX_ASM_CHARS]
    if len(original_asm) > MAX_ASM_CHARS:
        truncated_asm += "\n; ... (truncated)"
    prompt += f"Original Assembly Code:\n```asm\n{truncated_asm}\n```\n\n"
    
    prompt += f"Original Ghidra Decompilation:\n```{language}\n{original_ghidra}\n```\n\n"
    
    prompt += f"Current Decompiled Code (INCORRECT):\n```{language}\n{current_code}\n```\n\n"
    
    prompt += f"Function Summary:\n{function_summary}\n\n"
    
    prompt += f"VexHelix Verification Result: DIFFERENT (semantic mismatch detected)\n\n"
    
    # Add divergence details if available (VexHelix provides concrete counterexamples)
    if vexhelix_result.divergences:
        prompt += "Detected Divergences (inputs that cause different outputs):\n"
        for i, div in enumerate(vexhelix_result.divergences[:3]):  # Limit to 3
            prompt += f"\nDivergence {i+1}:\n"
            if div.get('inputs'):
                prompt += "  Input values:\n"
                for inp in div['inputs']:
                    prompt += f"    - {inp.get('name', 'arg')}: {inp.get('value', '?')} (hex: {inp.get('hex', '?')})\n"
            if div.get('orig_output'):
                prompt += f"  Original output: {div['orig_output'].get('value', '?')} (hex: {div['orig_output'].get('hex', '?')})\n"
            if div.get('dec_output'):
                prompt += f"  Your output: {div['dec_output'].get('value', '?')} (hex: {div['dec_output'].get('hex', '?')})\n"
        prompt += "\n"
    
    # Add statistics if available
    if vexhelix_result.statistics:
        stats = vexhelix_result.statistics
        prompt += f"Execution Statistics:\n"
        prompt += f"  - States explored (original): {stats.get('states_orig', '?')}\n"
        prompt += f"  - States explored (decompiled): {stats.get('states_dec', '?')}\n"
        prompt += f"  - Path pairs compared: {stats.get('comparisons_attempted', '?')}\n\n"
    
    prompt += "Please provide the corrected function that fixes the logical bug.\n"
    prompt += "Focus on matching the exact behavior shown in the assembly and Ghidra code.\n"
    
    return prompt


# =============================================================================
# COMPILATION UTILITIES
# =============================================================================

def compile_code(c_code: str, language: str, temp_dir: Path) -> Tuple[bool, str, Optional[Path]]:
    """
    Compile code and return (success, message, executable_path).
    """
    file_extension = "cpp" if language == "cpp" else "c"
    source_file = temp_dir / f"code.{file_extension}"
    executable_path = temp_dir / "executable.out"
    
    with open(source_file, "w") as f:
        f.write(c_code)
    
    status, message = c.compile_source(
        source_file_path=source_file,
        output_file_path=executable_path,
        opt=OptimizationLevel.O0,
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
        
        status, message = c.compile_source(
            source_file_path=str(c_file_path),
            output_file_path=str(executable_path),
            opt=OptimizationLevel.O0,
            is_cpp=(data['language'] == "cpp"),
            c_flag=True
        )
        
        if not status:
            print(f"[Compile] Failed for index {data['index']}: {message[:100]}")
            return CompilationResult(
                index=data['index'],
                success=False,
                executable_path=None,
                error_message=message,
                data=data
            )
        
        return CompilationResult(
            index=data['index'],
            success=True,
            executable_path=executable_path,
            error_message=None,
            data=data
        )
    
    except Exception as e:
        print(f"[Compile] Exception for index {data['index']}: {e}")
        return CompilationResult(
            index=data['index'],
            success=False,
            executable_path=None,
            error_message=str(e),
            data=data
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


# =============================================================================
# CONCURRENT STATIC REPAIR (NEW IN V6)
# =============================================================================

def static_repair_single_task(
    task: RepairTask,
    llm_interface: LLMInterface
) -> RepairResult:
    """
    Perform static repair for a single task.
    This function runs in a thread pool for concurrent execution.
    """
    func_data = task.func_data
    prog_data = task.prog_data
    temp_dir = task.temp_dir
    
    stats = {
        'static_repair_iterations': 0,
        'compile_attempts': 0
    }
    
    try:
        # Get initial code
        c_code = func_data.get('ghidra_code', '')
        function_summary = func_data.get('function_summary', '')
        language = prog_data.get('language', 'c')
        
        # Build context
        callgraph = prog_data.get('callgraph', {})
        caller_and_callee_summary = gen_context_summary(callgraph)
        function_sog = ""
        
        # Generate initial LLM response
        initial_prompt = get_initial_prompt(
            c_code=c_code,
            function_summary=function_summary,
            caller_and_callee_summary=caller_and_callee_summary,
            function_sog=function_sog,
            language=language
        )
        
        optimized_code = llm_interface.generate(initial_prompt)
        
        # Static repair loop
        for static_iter in range(MAX_STATIC_REPAIR_PER_CYCLE):
            stats['compile_attempts'] += 1
            
            compile_success, compile_message, _ = compile_code(
                optimized_code, language, temp_dir
            )
            
            if compile_success:
                return RepairResult(
                    index=task.index,
                    success=True,
                    optimized_code=optimized_code,
                    compile_success=True,
                    needs_semantic_check=True,
                    stats=stats
                )
            
            # Repair compilation error
            stats['static_repair_iterations'] += 1
            e = ErrorNormalizer()
            error_prompt = e.format_for_llm(compile_message)
            
            repair_prompt = get_static_repair_prompt(
                c_code=optimized_code,
                compilation_errors=error_prompt,
                function_summary=function_summary,
                caller_and_callee_summary=caller_and_callee_summary,
                function_sog=function_sog,
                language=language
            )
            
            optimized_code = llm_interface.generate(repair_prompt)
        
        # Still doesn't compile after max attempts
        return RepairResult(
            index=task.index,
            success=False,
            optimized_code=optimized_code,
            compile_success=False,
            needs_semantic_check=False,
            stats=stats,
            error_message="Max static repair iterations reached"
        )
        
    except Exception as e:
        return RepairResult(
            index=task.index,
            success=False,
            optimized_code="",
            compile_success=False,
            needs_semantic_check=False,
            stats=stats,
            error_message=str(e)
        )


def batch_static_repair(
    tasks: List[RepairTask],
    llm_interface: LLMInterface
) -> List[RepairResult]:
    """
    Perform static repair on multiple tasks concurrently.
    This is the key performance improvement in v6.
    """
    print(f"\n[Concurrent Static Repair] Processing {len(tasks)} tasks with {CONCURRENT_REPAIR_SIZE} workers...")
    results = []
    
    with ThreadPoolExecutor(max_workers=CONCURRENT_REPAIR_SIZE) as executor:
        futures = {
            executor.submit(static_repair_single_task, task, llm_interface): task
            for task in tasks
        }
        
        for future in as_completed(futures):
            task = futures[future]
            try:
                result = future.result()
                results.append(result)
                status = "✓" if result.compile_success else "✗"
                lang = task.prog_data.get('language', 'c')
                print(f"[Concurrent Static Repair] {status} Task {task.index} ({lang}): "
                      f"compile={result.compile_success}, repairs={result.stats.get('static_repair_iterations', 0)}")
            except Exception as e:
                print(f"[Concurrent Static Repair] ✗ Task {task.index} exception: {e}")
                results.append(RepairResult(
                    index=task.index,
                    success=False,
                    optimized_code="",
                    compile_success=False,
                    needs_semantic_check=False,
                    error_message=str(e)
                ))
    
    compiled = sum(1 for r in results if r.compile_success)
    print(f"[Concurrent Static Repair] Completed: {compiled}/{len(tasks)} compile successfully\n")
    return results


# =============================================================================
# MAIN OPTIMIZATION LOOP WITH VEXHELIX
# =============================================================================

def gen_context_summary(callgraph: Dict[str, List[str]]) -> str:
    """Generate caller/callee context summary."""
    prompt = ""
    for function, callees in callgraph.items():
        if function == "func0":
            prompt += f"{function} calls {', '.join(callees) if callees else 'no functions'}\n"
    return prompt


def get_optimized_code_v6(
    c_code: str,
    function_summary: str,
    caller_and_callee_summary: str,
    function_sog: str,
    language: str,
    llm_interface: LLMInterface,
    original_binary_path: Path,
    function_name: str,
    original_asm: str,
    original_ghidra: str,
    num_args: int = 3
) -> Tuple[bool, str, Dict]:
    """
    Enhanced optimization with VexHelix semantic verification.
    
    This is the main repair loop that:
    1. Attempts static repair until code compiles
    2. Verifies semantic equivalence with VexHelix
    3. Performs semantic repair if divergences found
    
    Supports both C and C++ (unlike v2 which skipped C++)
    
    Returns:
        (success, optimized_code, stats)
    """
    stats = {
        'static_repair_iterations': 0,
        'semantic_repair_iterations': 0,
        'vexhelix_calls': 0,
        'vexhelix_equivalent_achieved': False,
        'final_result': None,
        'language': language
    }
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Initial LLM prompt
        print(f"[Optimize V6] Starting optimization for {function_name} ({language})...")
        initial_prompt = get_initial_prompt(
            c_code=c_code,
            function_summary=function_summary,
            caller_and_callee_summary=caller_and_callee_summary,
            function_sog=function_sog,
            language=language
        )
        
        optimized_code = llm_interface.generate(initial_prompt)
        
        # Main repair loop
        for iteration in range(MAX_REPAIR_ITERATIONS):
            print(f"\n[Optimize V6] === Iteration {iteration + 1}/{MAX_REPAIR_ITERATIONS} ===")
            
            # Phase 1: Static Repair (ensure compilation)
            compile_success, compile_message, executable_path = compile_code(
                optimized_code, language, temp_path
            )
            
            if not compile_success:
                print(f"[Static Repair] Code doesn't compile, fixing...")
                stats['static_repair_iterations'] += 1
                
                e = ErrorNormalizer()
                error_prompt = e.format_for_llm(compile_message)
                
                repair_prompt = get_static_repair_prompt(
                    c_code=optimized_code,
                    compilation_errors=error_prompt,
                    function_summary=function_summary,
                    caller_and_callee_summary=caller_and_callee_summary,
                    function_sog=function_sog,
                    language=language
                )
                
                optimized_code = llm_interface.generate(repair_prompt)
                print(f"[Static Repair] Received repaired code from LLM")
                continue  # Go back to compilation check
            
            print(f"[Static Repair] ✓ Code compiles successfully")
            
            # Phase 2: Semantic Verification (VexHelix)
            # NOTE: Unlike D-Helix, VexHelix FULLY supports both C and C++
            print(f"[Semantic Verify] Calling VexHelix API ({language})...")
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
                # Check if it's a compilation error on VexHelix side
                if vexhelix_result.compilation_error:
                    print(f"[Semantic Verify] VexHelix compilation error: {vexhelix_result.compilation_error[:100]}")
                    # Treat as static repair needed
                    stats['static_repair_iterations'] += 1
                    
                    repair_prompt = get_static_repair_prompt(
                        c_code=optimized_code,
                        compilation_errors=vexhelix_result.compilation_error,
                        function_summary=function_summary,
                        caller_and_callee_summary=caller_and_callee_summary,
                        function_sog=function_sog,
                        language=language
                    )
                    optimized_code = llm_interface.generate(repair_prompt)
                    continue
                
                print(f"[Semantic Verify] VexHelix API error: {vexhelix_result.error_message}")
                print(f"[Semantic Verify] Continuing with compilable code...")
                stats['final_result'] = 'vexhelix_error'
                return True, optimized_code, stats
            
            if vexhelix_result.status == 'timeout':
                print(f"[Semantic Verify] VexHelix timeout - returning compilable code")
                stats['final_result'] = 'vexhelix_timeout'
                return True, optimized_code, stats
            
            if vexhelix_result.status == 'equivalent' or vexhelix_result.equivalent:
                print(f"[Semantic Verify] ✓✓✓ EQUIVALENT - Code is semantically correct!")
                stats['vexhelix_equivalent_achieved'] = True
                stats['final_result'] = 'equivalent'
                return True, optimized_code, stats
            
            # Phase 3: Semantic Repair (fix logical bugs)
            print(f"[Semantic Verify] ✗ DIFFERENT - Logical bug detected")
            print(f"[Semantic Repair] Attempting to fix logical errors...")
            stats['semantic_repair_iterations'] += 1
            
            semantic_prompt = get_semantic_repair_prompt(
                original_asm=original_asm,
                original_ghidra=original_ghidra,
                current_code=optimized_code,
                function_summary=function_summary,
                vexhelix_result=vexhelix_result,
                language=language
            )
            
            optimized_code = llm_interface.generate(semantic_prompt)
            print(f"[Semantic Repair] Received semantically repaired code from LLM")
            # Loop will now re-check compilation and semantics
        
        # Max iterations reached
        print(f"[Optimize V6] Max iterations ({MAX_REPAIR_ITERATIONS}) reached")
        
        # Do final check
        compile_success, _, _ = compile_code(optimized_code, language, temp_path)
        
        if compile_success:
            stats['final_result'] = 'max_iterations_compilable'
            return True, optimized_code, stats
        else:
            stats['final_result'] = 'max_iterations_not_compilable'
            return False, optimized_code, stats


# =============================================================================
# DATA ENRICHMENT
# =============================================================================

def split_enrichment(data: Dict, ghidra_result: Dict, original_binary_path: Path) -> Dict:
    """Enrich function data using pre-extracted Ghidra analysis."""
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
# BATCH OPTIMIZATION WITH CONCURRENT REPAIR
# =============================================================================

def batch_optimize_functions_v6(enriched_programs: List[Dict]) -> List[Dict]:
    """
    Optimize multiple functions using batched LLM calls with VexHelix verification.
    
    Key improvements in v6:
    - Concurrent static repair for multiple programs
    - Full C++ support via VexHelix
    - Better counterexample utilization
    """
    print(f"\n[Batch Optimize V6] Starting optimization of {len(enriched_programs)} programs...")
    
    # Step 1: Batch generate summaries
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
    
    # Step 3: Optimize with VexHelix verification
    # Note: Semantic verification must be sequential due to VexHelix resource constraints
    for prog_idx, prog_data in enumerate(enriched_programs):
        for func_data in prog_data['functions']:
            lang = prog_data.get('language', 'c')
            print(f"\n[Batch Optimize V6] Processing function {func_data['f_name']} ({lang}) in program {prog_idx}...")
            
            optimization_success, optimized_code, stats = get_optimized_code_v6(
                c_code=func_data['ghidra_code'],
                function_summary=func_data['function_summary'],
                caller_and_callee_summary=gen_context_summary(prog_data['callgraph']),
                function_sog="",
                language=lang,
                llm_interface=llm_interface,
                original_binary_path=Path(prog_data['original_binary_path']),
                function_name=func_data['f_name'],
                original_asm=func_data.get('asm', ''),
                original_ghidra=func_data['ghidra_code'],
                num_args=3  # Default, could be parsed from signature
            )
            
            func_data['optimization_status'] = optimization_success
            func_data['optimized_code'] = optimized_code
            func_data['optimization_stats'] = stats
            
            print(f"[Batch Optimize V6] Stats for {func_data['f_name']} ({lang}):")
            print(f"  - Static repairs: {stats['static_repair_iterations']}")
            print(f"  - Semantic repairs: {stats['semantic_repair_iterations']}")
            print(f"  - VexHelix calls: {stats['vexhelix_calls']}")
            print(f"  - Equivalent achieved: {stats['vexhelix_equivalent_achieved']}")
            print(f"  - Final result: {stats['final_result']}")
    
    print(f"[Batch Optimize V6] Completed optimization\n")
    return enriched_programs


# =============================================================================
# MAIN PROCESSING PIPELINE
# =============================================================================

def process_batch(batch_items: List[Dict], temp_base_dir: Path) -> List[Dict]:
    """
    Process a batch of items through the entire pipeline with VexHelix verification.
    """
    # Step 1: Compile all programs in parallel (original code)
    compile_results = batch_compile_programs(batch_items, temp_base_dir)
    
    successful_compilations = [(r.index, r.executable_path) for r in compile_results if r.success]
    
    if not successful_compilations:
        print("[Batch] No successful compilations in this batch")
        return []
    
    # Step 2: Batch Ghidra analysis
    ghidra_results = batch_ghidra_analysis(successful_compilations)
    
    # Step 3: Enrich data with Ghidra results
    enriched_programs = []
    for compile_result in compile_results:
        if not compile_result.success:
            continue
        
        ghidra_result = ghidra_results.get(compile_result.index)
        if ghidra_result is None:
            print(f"[Batch] No Ghidra result for index {compile_result.index}")
            continue
        
        enriched_data = split_enrichment(
            compile_result.data, 
            ghidra_result,
            compile_result.executable_path
        )
        enriched_programs.append(enriched_data)
    
    # Step 4: Batch LLM optimization with VexHelix verification
    optimized_programs = batch_optimize_functions_v6(enriched_programs)
    
    return optimized_programs


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
    Process the humaneval decompile json file with batched operations and VexHelix verification.
    
    Args:
        json_path: Path to humaneval-decompile.json
        start_index: Starting index (for resuming)
        limit: Maximum number of items to process (for testing)
    """
    output_file_path = output_dir / "batched_enriched_humaneval_decompile_v6.json"
    output_file_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(json_path, "r") as f:
        humaneval_data = json.load(f)
    
    # Apply start_index and limit
    if limit:
        humaneval_data = humaneval_data[start_index:start_index + limit]
    else:
        humaneval_data = humaneval_data[start_index:]
    
    # Count languages
    c_count = sum(1 for d in humaneval_data if d['language'] == 'c')
    cpp_count = sum(1 for d in humaneval_data if d['language'] == 'cpp')
    
    print(f"\n{'='*70}")
    print(f"MissionDecompile V6 - VexHelix Semantic Verification")
    print(f"{'='*70}")
    print(f"Processing {len(humaneval_data)} functions from HumanEval dataset")
    print(f"  - C programs: {c_count}")
    print(f"  - C++ programs: {cpp_count}")
    print(f"VexHelix API: {VEXHELIX_API_URL}")
    print(f"Concurrent repair workers: {CONCURRENT_REPAIR_SIZE}")
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
    
    parser = argparse.ArgumentParser(description="MissionDecompile V6 - VexHelix Semantic Verification")
    parser.add_argument("--start", type=int, default=0, help="Starting index")
    parser.add_argument("--limit", type=int, default=None, help="Maximum items to process")
    parser.add_argument("--skip-api-check", action="store_true", help="Skip VexHelix API check")
    args = parser.parse_args()
    
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
            print("  Or use --skip-api-check to continue anyway (semantic verification will fail)")
            return
    
    process_humaneval_decompile(json_path, args.start, args.limit)


if __name__ == "__main__":
    main()
