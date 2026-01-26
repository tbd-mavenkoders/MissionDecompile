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

# Thread-safe progress tracking (like test_pipeline_20.py)
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
# Summary uses LLM, VexHelix repair loop uses LLM heavily
# So we split: 12 for summary + 12 for vexhelix = 24 max LLM concurrency
PIPELINE_COMPILE_WIDTH = 20   # Compile is fast (gcc subprocess)
PIPELINE_GHIDRA_WIDTH = 12     # Ghidra is memory-heavy, limit parallelism
PIPELINE_SUMMARY_WIDTH = 12   # LLM bound: 12 concurrent summary requests
PIPELINE_VEXHELIX_WIDTH = 12  # LLM bound: 12 concurrent repair loops (each uses LLM)

# Legacy batching configuration (used by non-pipelined functions)
COMPILATION_BATCH_SIZE = 20
GHIDRA_BATCH_SIZE = 8
LLM_BATCH_SIZE = 12  # Match pipeline summary width

# Concurrent static repair configuration (legacy, not used in pipelined mode)
CONCURRENT_REPAIR_SIZE = 12  # Match pipeline vexhelix width

# VexHelix API configuration (replaces D-Helix)
VEXHELIX_API_URL = "http://127.0.0.1:8001"
VEXHELIX_TIMEOUT = 180  # seconds per verification (increased for complex functions)
VEXHELIX_LOOP_BOUND = 5  # Maximum loop iterations in symbolic execution
VEXHELIX_RETRIES = 3  # Number of retries for transient failures

# Repair configuration
MAX_REPAIR_ITERATIONS = 7  # Reduced from 15 - better prompts need fewer iterations
MAX_STATIC_REPAIR_PER_CYCLE = 3  # Max static repair attempts before checking semantics
MAX_STAGNANT_ITERATIONS = 4  # Early exit if divergence count doesn't improve
PARALLEL_REPAIR_WORKERS = 12  # Match pipeline vexhelix width (LLM bound)

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
    
    IMPROVED in v6: Retry logic with exponential backoff for transient failures.
    
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
    lang_str = "cpp" if language.lower() == "cpp" else "c"
    last_error = None
    
    for attempt in range(VEXHELIX_RETRIES):
        try:
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
                last_error = f"HTTP {response.status_code}: {response.text[:500]}"
                print(f"[VexHelix] Error: {last_error}")
                if response.status_code >= 500:  # Server error, retry
                    print(f"[VexHelix] Server error (attempt {attempt + 1}/{VEXHELIX_RETRIES}), retrying...")
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue
                # Client error (4xx), don't retry
                return VexHelixResult(
                    success=False,
                    status='error',
                    equivalent=None,
                    divergences=None,
                    statistics=None,
                    error_message=last_error,
                    compilation_error=None
                )
        
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_error = str(e)[:200]
            if attempt < VEXHELIX_RETRIES - 1:
                print(f"[VexHelix] Connection error (attempt {attempt + 1}/{VEXHELIX_RETRIES}), retrying...")
                time.sleep(2 ** attempt)  # Exponential backoff: 1s, 2s, 4s
                continue
        except Exception as e:
            return VexHelixResult(
                success=False,
                status='error',
                equivalent=None,
                divergences=None,
                statistics=None,
                error_message=str(e)[:200],
                compilation_error=None
            )
    
    # All retries exhausted
    print(f"[VexHelix] Failed after {VEXHELIX_RETRIES} retries: {last_error}")
    return VexHelixResult(
        success=False,
        status='error',
        equivalent=None,
        divergences=None,
        statistics=None,
        error_message=f"Failed after {VEXHELIX_RETRIES} retries: {last_error}",
        compilation_error=None
    )


# =============================================================================
# PROMPT GENERATION
# =============================================================================

def get_initial_prompt(c_code: str, function_summary: str, caller_and_callee_summary: str, 
                      function_sog: str, language: str, asm: str = "") -> str:
    """
    Generate the initial prompt for the repair tool.
    
    IMPROVED in v6: Includes assembly as ground truth with Ghidra warning.
    The LLM should prioritize assembly over Ghidra when they conflict.
    """
    initial_prompt = config["prompts"]["system_prompt"]
    
    # Truncate assembly but keep enough for context
    truncated_asm = asm[:5000] if asm else ""
    if len(asm) > 5000:
        truncated_asm += "\n; ... (truncated)"
    
    prompt = f"""{initial_prompt}

IMPORTANT: Ghidra's decompilation may have errors. The assembly shows the true behavior.
Common Ghidra mistakes:
- Wrong return types (void instead of float/int)
- Missing float operations (addss, mulss, divss instructions ignored)
- Empty loop bodies (operations inside loops omitted)
- Wrong parameter types (long instead of float*)

If Ghidra shows 'void' but assembly uses xmm0 for return, the function returns float/double.
If assembly has addss/subss/mulss/divss, the code MUST have float arithmetic.

Assembly (ground truth - this is what the binary ACTUALLY does):
```asm
{truncated_asm}
```

Ghidra decompilation (may be incorrect - use as rough guide):
```{language}
{c_code}
```

Function Summary: {function_summary}
"""
    
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
    Generate robust semantic repair prompt - assembly is ground truth, Ghidra is unreliable.
    
    IMPROVED in v6: Detailed guidance on common Ghidra mistakes and how to fix them.
    This prompt is critical for recovering from Ghidra decompilation failures.
    """
    # Truncate assembly but keep more of it (it's the ground truth!)
    truncated_asm = original_asm[:6000] if original_asm else ""
    if len(original_asm) > 6000:
        truncated_asm += "\n; ... (truncated)"
    
    prompt = f"""You are fixing decompiled code that produces WRONG outputs. The verifier found semantic differences.

CRITICAL: The ASSEMBLY is the ground truth - it shows exactly what the binary does.
Ghidra's decompilation is OFTEN WRONG and should only be used as a rough guide.

COMMON GHIDRA MISTAKES TO CHECK FOR:
1. WRONG RETURN TYPE: Ghidra often shows 'void' when the function actually returns int/float/double
   - Look for floating-point instructions (movss, movsd, addss, mulss, divss, cvtsi2ss, etc.) → function likely returns float
   - Look for xmm0 being set before ret → return value is in xmm0 (float/double)
   - Look for eax/rax being set before ret → return value is int/long
2. MISSING FLOATING-POINT OPERATIONS: Ghidra sometimes omits float math entirely
   - If asm has addss/subss/mulss/divss, the code MUST have float arithmetic
   - cvtsi2ss = int to float conversion
   - cvttss2si = float to int conversion
3. WRONG PARAMETER TYPES: long/int instead of float*, void* instead of actual types
   - If asm dereferences param and uses movss, it's a float pointer
4. EMPTY LOOP BODIES: Ghidra sometimes shows loops that do nothing
   - Check what instructions are INSIDE the loop in assembly
   - Loops usually accumulate values, check for add/mul instructions with memory operands

ASSEMBLY (GROUND TRUTH - this is what the binary ACTUALLY does):
```asm
{truncated_asm}
```

GHIDRA DECOMPILATION (UNRELIABLE - use as rough guide only):
```{language}
{original_ghidra}
```

YOUR CURRENT CODE (WRONG - produces incorrect output):
```{language}
{current_code}
```

Function Summary: {function_summary}

VERIFICATION RESULT: DIFFERENT (your code doesn't match the binary's behavior)
"""
    
    # Format divergences with clear explanation - show more divergences (5 instead of 3)
    if vexhelix_result.divergences:
        prompt += "\nCOUNTEREXAMPLES (inputs where your code gives wrong answer):\n"
        for i, div in enumerate(vexhelix_result.divergences[:5]):
            prompt += f"\nTest case {i+1}:\n"
            if div.get('inputs'):
                prompt += "  Inputs: "
                inputs_str = ", ".join([f"{inp.get('name', 'arg')}={inp.get('value', '?')}" for inp in div['inputs']])
                prompt += inputs_str + "\n"
            if div.get('orig_output'):
                orig = div['orig_output']
                prompt += f"  Expected (from binary): {orig.get('value', '?')}"
                if orig.get('hex'):
                    prompt += f" (0x{orig.get('hex', '?')})"
                prompt += "\n"
            if div.get('dec_output'):
                dec = div['dec_output']
                prompt += f"  Your output: {dec.get('value', '?')}"
                if dec.get('hex'):
                    prompt += f" (0x{dec.get('hex', '?')})"
                prompt += "\n"
    
    prompt += """
TASK: Fix your code to match the ASSEMBLY behavior. Steps:
1. Analyze the assembly to understand what the function REALLY does
2. Identify where Ghidra went wrong (return type? missing operations? wrong types?)
3. Rewrite the function based on assembly, using Ghidra only as a loose guide
4. Make sure your return type and parameter types match what the assembly expects

Output ONLY the corrected function code."""
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
    num_args: int = 3,
    task_id: str = ""
) -> Tuple[bool, str, Dict]:
    """
    Enhanced optimization with VexHelix semantic verification.
    
    This is the main repair loop that:
    1. Attempts static repair until code compiles
    2. Verifies semantic equivalence with VexHelix
    3. Performs semantic repair if divergences found
    4. Early exit if divergence count stagnates (doesn't improve)
    
    Supports both C and C++ (unlike v2 which skipped C++)
    
    Returns:
        (success, optimized_code, stats)
    """
    prefix = f"[{task_id}]" if task_id else "[Optimize V6]"
    
    stats = {
        'static_repair_iterations': 0,
        'semantic_repair_iterations': 0,
        'vexhelix_calls': 0,
        'vexhelix_equivalent_achieved': False,
        'final_result': None,
        'language': language,
        'divergence_history': []  # Track divergence counts
    }
    
    # Track divergence improvement
    best_divergence_count = float('inf')
    stagnant_count = 0
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Initial LLM prompt - NOW INCLUDES ASSEMBLY AS GROUND TRUTH
        print(f"{prefix} Starting optimization for {function_name} ({language})...", flush=True)
        initial_prompt = get_initial_prompt(
            c_code=c_code,
            function_summary=function_summary,
            caller_and_callee_summary=caller_and_callee_summary,
            function_sog=function_sog,
            language=language,
            asm=original_asm  # Pass assembly to initial prompt
        )
        
        optimized_code = llm_interface.generate(initial_prompt)
        
        # Main repair loop
        for iteration in range(MAX_REPAIR_ITERATIONS):
            print(f"{prefix} === Iteration {iteration + 1}/{MAX_REPAIR_ITERATIONS} ===")
            
            # Phase 1: Static Repair (ensure compilation)
            compile_success, compile_message, executable_path = compile_code(
                optimized_code, language, temp_path
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
                    language=language
                )
                
                optimized_code = llm_interface.generate(repair_prompt)
                print(f"{prefix} [Static] Received repaired code")
                continue  # Go back to compilation check
            
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
                # Check if it's a compilation error on VexHelix side
                if vexhelix_result.compilation_error:
                    print(f"{prefix} [Semantic] VexHelix compile error, fixing...")
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
                
                print(f"{prefix} [Semantic] VexHelix API error: {vexhelix_result.error_message}")
                stats['final_result'] = 'vexhelix_error'
                return True, optimized_code, stats
            
            if vexhelix_result.status == 'timeout':
                print(f"{prefix} [Semantic] VexHelix timeout")
                stats['final_result'] = 'vexhelix_timeout'
                return True, optimized_code, stats
            
            if vexhelix_result.status == 'equivalent' or vexhelix_result.equivalent:
                print(f"{prefix} ✓✓✓ EQUIVALENT!")
                stats['vexhelix_equivalent_achieved'] = True
                stats['final_result'] = 'equivalent'
                return True, optimized_code, stats
            
            # Phase 3: Check for stagnation
            current_divergences = len(vexhelix_result.divergences or [])
            stats['divergence_history'].append(current_divergences)
            print(f"{prefix} [Semantic] ✗ DIFFERENT - {current_divergences} divergences")
            
            # Check if improving
            if current_divergences < best_divergence_count:
                best_divergence_count = current_divergences
                stagnant_count = 0
                print(f"{prefix} [Semantic] Improvement! Best so far: {best_divergence_count}")
            else:
                stagnant_count += 1
                print(f"{prefix} [Semantic] No improvement ({stagnant_count}/{MAX_STAGNANT_ITERATIONS})")
                
                if stagnant_count >= MAX_STAGNANT_ITERATIONS:
                    print(f"{prefix} [Semantic] ⚠ Stagnation detected - early exit")
                    print(f"{prefix} Divergence history: {stats['divergence_history']}")
                    stats['final_result'] = 'stagnant_divergences'
                    return True, optimized_code, stats
            
            # Phase 4: Semantic Repair
            print(f"{prefix} [Semantic] Attempting fix...")
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
            print(f"{prefix} [Semantic] Received repaired code")
        
        # Max iterations reached
        print(f"{prefix} Max iterations ({MAX_REPAIR_ITERATIONS}) reached")
        print(f"{prefix} Divergence history: {stats['divergence_history']}")
        
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
# BATCH OPTIMIZATION WITH STREAMING PARALLEL REPAIR
# =============================================================================

def batch_optimize_functions_v6(enriched_programs: List[Dict]) -> List[Dict]:
    """
    Optimize multiple functions using STREAMING PARALLEL repair loops with VexHelix verification.
    
    IMPROVED in v6 (from test_pipeline_20.py learnings):
    - TRUE STREAMING parallelism: tasks start immediately as slots free up
    - Thread-safe progress tracking with print_lock
    - 24 concurrent workers (matching VexHelix worker pool)
    - Full C++ support via VexHelix
    - Early exit on stagnant divergences
    - Better counterexample utilization
    - Assembly included in initial prompt as ground truth
    """
    global active_count, completed_count, total_tasks
    
    print(f"\n{'='*70}")
    print(f"[Batch Optimize V6] Starting STREAMING PARALLEL optimization")
    print(f"[Batch Optimize V6] Programs: {len(enriched_programs)}")
    print(f"[Batch Optimize V6] Concurrent workers: {PARALLEL_REPAIR_WORKERS}")
    print(f"[Batch Optimize V6] Max iterations: {MAX_REPAIR_ITERATIONS}")
    print(f"[Batch Optimize V6] Stagnation limit: {MAX_STAGNANT_ITERATIONS}")
    print(f"{'='*70}")
    
    # Step 1: Batch generate summaries first (this is fast)
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
    
    # Step 3: Build list of tasks for parallel execution
    optimization_tasks = []
    for prog_idx, prog_data in enumerate(enriched_programs):
        for func_data in prog_data['functions']:
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
    
    print(f"\n[Streaming] Prepared {total_tasks} optimization tasks")
    print(f"[Streaming] Starting streaming execution...\n")
    
    # Step 4: Run full repair loops in STREAMING parallel
    results_map = {}  # Map prog_idx -> result
    
    def run_single_optimization(task):
        """Run a single full optimization loop with progress tracking."""
        global active_count, completed_count
        
        prog_data = task['prog_data']
        func_data = task['func_data']
        prog_idx = task['prog_idx']
        task_id = task['task_id']
        lang = prog_data.get('language', 'c')
        idx = prog_data.get('index', prog_idx)
        
        # Track active count
        with print_lock:
            active_count += 1
            print(f"  [START] {task_id} ({lang}) idx={idx} - active: {active_count}", flush=True)
        
        start_time = time.time()
        
        try:
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
                num_args=3,
                task_id=task_id
            )
            
            duration = time.time() - start_time
            stats['duration'] = duration
            
            # Update progress with thread safety
            with print_lock:
                active_count -= 1
                completed_count += 1
                status = stats.get('final_result', 'unknown')
                sym = "✓" if status == 'equivalent' else "✗"
                print(f"[{sym}] {task_id} ({lang}): {status} "
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
    
    # Execute in STREAMING parallel with ThreadPoolExecutor
    # True streaming: completed tasks immediately free slots for new tasks
    executor = ThreadPoolExecutor(max_workers=PARALLEL_REPAIR_WORKERS)
    try:
        # Submit all tasks - executor handles queuing internally
        futures = {
            executor.submit(run_single_optimization, task): task
            for task in optimization_tasks
        }
        
        # Process completions as they arrive (true streaming)
        for future in as_completed(futures):
            try:
                result = future.result()
                prog_idx = result['prog_idx']
                results_map[prog_idx] = result
            except Exception as e:
                task = futures[future]
                print(f"[ERROR] Task P{task['prog_idx']} future exception: {e}", flush=True)
    finally:
        # Shutdown without waiting (all futures already completed)
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
    
    # Print comprehensive summary
    equivalent_count = sum(1 for r in results_map.values() 
                          if r['stats'].get('final_result') == 'equivalent')
    stagnant_count = sum(1 for r in results_map.values() 
                         if r['stats'].get('final_result') == 'stagnant_divergences')
    timeout_count = sum(1 for r in results_map.values() 
                        if r['stats'].get('final_result') == 'vexhelix_timeout')
    error_count = sum(1 for r in results_map.values() 
                      if r['stats'].get('final_result') in ('exception', 'vexhelix_error'))
    max_iter_count = sum(1 for r in results_map.values() 
                         if 'max_iterations' in str(r['stats'].get('final_result', '')))
    
    # Calculate average duration
    durations = [r['stats'].get('duration', 0) for r in results_map.values() if r['stats'].get('duration')]
    avg_duration = sum(durations) / len(durations) if durations else 0
    
    # Count by language
    c_equiv = sum(1 for task in optimization_tasks 
                  if task['prog_data'].get('language') == 'c' 
                  and results_map.get(task['prog_idx'], {}).get('stats', {}).get('final_result') == 'equivalent')
    cpp_equiv = sum(1 for task in optimization_tasks 
                    if task['prog_data'].get('language') == 'cpp' 
                    and results_map.get(task['prog_idx'], {}).get('stats', {}).get('final_result') == 'equivalent')
    c_total = sum(1 for task in optimization_tasks if task['prog_data'].get('language') == 'c')
    cpp_total = sum(1 for task in optimization_tasks if task['prog_data'].get('language') == 'cpp')
    
    print(f"\n{'='*70}")
    print(f"[Batch Optimize V6] STREAMING PARALLEL optimization complete!")
    print(f"{'='*70}")
    print(f"  Equivalent: {equivalent_count}/{total_tasks} ({100*equivalent_count/total_tasks:.0f}%)")
    print(f"    C:   {c_equiv}/{c_total}")
    print(f"    C++: {cpp_equiv}/{cpp_total}")
    print(f"  Stagnant (early exit): {stagnant_count}")
    print(f"  Timeout: {timeout_count}")
    print(f"  Errors: {error_count}")
    print(f"  Max iterations: {max_iter_count}")
    print(f"  Avg time per sample: {avg_duration:.1f}s")
    print(f"{'='*70}\n")
    
    return enriched_programs


# =============================================================================
# PIPELINED ARCHITECTURE - LIKE CPU PIPELINE WITH STAGES AND QUEUES
# =============================================================================
# 
# ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
# │  COMPILE    │──►│   GHIDRA    │──►│  SUMMARIES  │──►│  VEXHELIX   │
# │  width=20   │   │   width=8   │   │  width=16   │   │  width=24   │
# └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
#       ↑                 ↑                 ↑                 ↑
#   compile_q         ghidra_q          summary_q         vexhelix_q
#
# Each stage pulls from its input queue, processes, pushes to next queue.
# Stages run CONCURRENTLY - no waiting for all items to complete a stage!
# =============================================================================

# Sentinel value to signal stage shutdown
PIPELINE_DONE = object()


def _pipeline_compile_stage(
    input_q: Queue, 
    output_q: Queue, 
    temp_base_dir: Path,
    dropped_counter: Dict,  # Thread-safe counter for dropped items
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


def _pipeline_ghidra_stage(
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


def _pipeline_summary_stage(
    input_q: Queue, 
    output_q: Queue, 
    dropped_counter: Dict,
    counter_lock: threading.Lock,
    stage_id: str = "SUMMARY"
):
    """Pipeline Stage 3: LLM summary generation."""
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
                
                # Enrich data with ghidra results
                enriched_data = split_enrichment(data, ghidra_result, compile_result.executable_path)
                
                # Generate summaries for all functions
                for func_data in enriched_data['functions']:
                    summary_prompt = config["prompts"]["summary_prompt"]
                    prompt = f"{summary_prompt}"
                    if func_data.get('ghidra_code'):
                        prompt += f"\n\nGhidra Code:\n```c\n{func_data['ghidra_code']}\n```"
                    if func_data.get('asm'):
                        prompt += f"\n\nAssembly Instructions:\n{func_data['asm'][:2000]}"
                    
                    func_data['function_summary'] = llm_interface.generate(prompt)
                
                with print_lock:
                    print(f"[{stage_id}] P{idx} ({lang}) ✓", flush=True)
                
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


def _pipeline_vexhelix_stage(
    input_q: Queue, 
    results: List,
    results_lock: threading.Lock,
    counters: Dict,
    total_tasks: int,
    stage_id: str = "VEXHELIX"
):
    """Pipeline Stage 4: VexHelix semantic repair loop."""
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
                
                with print_lock:
                    counters['active'] += 1
                    print(f"[{stage_id}] {task_id} ({lang}) START | active: {counters['active']}", flush=True)
                
                start_time = time.time()
                
                # Run VexHelix optimization loop for each function
                for func_data in enriched_data['functions']:
                    optimization_success, optimized_code, stats = get_optimized_code_v6(
                        c_code=func_data['ghidra_code'],
                        function_summary=func_data['function_summary'],
                        caller_and_callee_summary=gen_context_summary(enriched_data['callgraph']),
                        function_sog="",
                        language=lang,
                        llm_interface=llm_interface,
                        original_binary_path=Path(enriched_data['original_binary_path']),
                        function_name=func_data['f_name'],
                        original_asm=func_data.get('asm', ''),
                        original_ghidra=func_data['ghidra_code'],
                        num_args=3,
                        task_id=task_id
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
                    print(f"[{sym}] {task_id} ({lang}): {final_result} "
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


def process_batch_pipelined(batch_items: List[Dict], temp_base_dir: Path) -> List[Dict]:
    """
    Process a batch using TRUE PIPELINED ARCHITECTURE.
    
    Like a CPU pipeline:
    - Stage 1 (COMPILE):  width=20, fast
    - Stage 2 (GHIDRA):   width=8,  memory-heavy
    - Stage 3 (SUMMARY):  width=16, LLM I/O bound
    - Stage 4 (VEXHELIX): width=24, verification
    
    Items flow through stages via queues. Each stage runs CONCURRENTLY.
    No waiting for all items to complete a stage before starting the next!
    
    Example timeline:
    t=0:  P0,P1,P2... start compiling
    t=1:  P0 done compiling → goes to Ghidra | P3,P4... still compiling
    t=2:  P0 done Ghidra → goes to Summary | P1 enters Ghidra | P5,P6... compiling
    ...
    """
    total = len(batch_items)
    
    print(f"\n{'='*70}")
    print(f"[PIPELINED] TRUE CPU-STYLE PIPELINE ARCHITECTURE")
    print(f"{'='*70}")
    print(f"  Total programs: {total}")
    print(f"  Stage widths:")
    print(f"    COMPILE:  {PIPELINE_COMPILE_WIDTH} workers")
    print(f"    GHIDRA:   {PIPELINE_GHIDRA_WIDTH} workers")
    print(f"    SUMMARY:  {PIPELINE_SUMMARY_WIDTH} workers")
    print(f"    VEXHELIX: {PIPELINE_VEXHELIX_WIDTH} workers")
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
    
    # Dropped items counter (thread-safe) - items that failed at a stage and won't proceed
    dropped_counter = {'compile': 0, 'ghidra': 0, 'summary': 0}
    counter_lock = threading.Lock()
    
    # Start stage workers
    all_threads = []
    
    # Stage 1: Compile workers
    for _ in range(PIPELINE_COMPILE_WIDTH):
        worker_fn = _pipeline_compile_stage(compile_q, ghidra_q, temp_base_dir, dropped_counter, counter_lock)
        t = threading.Thread(target=worker_fn, daemon=True)
        t.start()
        all_threads.append(('compile', t))
    
    # Stage 2: Ghidra workers
    for _ in range(PIPELINE_GHIDRA_WIDTH):
        worker_fn = _pipeline_ghidra_stage(ghidra_q, summary_q, cfg_script, callgraph_script, dropped_counter, counter_lock)
        t = threading.Thread(target=worker_fn, daemon=True)
        t.start()
        all_threads.append(('ghidra', t))
    
    # Stage 3: Summary workers
    for _ in range(PIPELINE_SUMMARY_WIDTH):
        worker_fn = _pipeline_summary_stage(summary_q, vexhelix_q, dropped_counter, counter_lock)
        t = threading.Thread(target=worker_fn, daemon=True)
        t.start()
        all_threads.append(('summary', t))
    
    # Stage 4: VexHelix workers
    for _ in range(PIPELINE_VEXHELIX_WIDTH):
        worker_fn = _pipeline_vexhelix_stage(vexhelix_q, results, results_lock, counters, total)
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
    
    print(f"\n{'='*70}")
    print(f"[PIPELINED] Complete!")
    print(f"{'='*70}")
    print(f"  Processed: {len(results)}/{total}")
    if total_dropped > 0:
        print(f"  Dropped: {total_dropped} (compile:{dropped_counter['compile']}, ghidra:{dropped_counter['ghidra']}, summary:{dropped_counter['summary']})")
    print(f"  Equivalent: {equivalent_count}/{len(results)} ({100*equivalent_count/len(results) if results else 0:.0f}%)")
    print(f"    C:   {c_equiv}/{len(c_results)}")
    print(f"    C++: {cpp_equiv}/{len(cpp_results)}")
    print(f"{'='*70}\n")
    
    return results


# =============================================================================
# STREAMING PIPELINE - EACH PROGRAM FLOWS THROUGH ENTIRE PIPELINE INDEPENDENTLY
# =============================================================================

def process_single_program_streaming(
    data: Dict, 
    temp_base_dir: Path,
    cfg_script: Path,
    callgraph_script: Path
) -> Optional[Dict]:
    """
    Process a single program through the ENTIRE pipeline: compile → ghidra → summary → vexhelix.
    
    This is the atomic unit of the streaming pipeline. Each program is completely
    independent and can run in parallel with others.
    
    Returns enriched program data with optimization results, or None if failed.
    """
    global active_count, completed_count, total_tasks
    
    idx = data['index']
    lang = data.get('language', 'c')
    task_id = f"P{idx}"
    
    with print_lock:
        active_count += 1
        print(f"[STREAM] {task_id} ({lang}) START | active: {active_count}", flush=True)
    
    start_time = time.time()
    
    try:
        # =====================================================================
        # STEP 1: COMPILE
        # =====================================================================
        compile_result = compile_single_program(data, temp_base_dir)
        
        if not compile_result.success:
            with print_lock:
                active_count -= 1
                completed_count += 1
                print(f"[✗] {task_id} ({lang}): compile_failed | "
                      f"done: {completed_count}/{total_tasks}, active: {active_count}", flush=True)
            return None
        
        with print_lock:
            print(f"[STREAM] {task_id} ({lang}) compiled ✓", flush=True)
        
        # =====================================================================
        # STEP 2: GHIDRA ANALYSIS
        # =====================================================================
        ghidra_result = analyze_single_executable(
            idx, 
            compile_result.executable_path, 
            cfg_script, 
            callgraph_script
        )
        
        if ghidra_result is None:
            with print_lock:
                active_count -= 1
                completed_count += 1
                print(f"[✗] {task_id} ({lang}): ghidra_failed | "
                      f"done: {completed_count}/{total_tasks}, active: {active_count}", flush=True)
            return None
        
        with print_lock:
            print(f"[STREAM] {task_id} ({lang}) ghidra ✓", flush=True)
        
        # =====================================================================
        # STEP 3: ENRICH DATA
        # =====================================================================
        enriched_data = split_enrichment(data, ghidra_result, compile_result.executable_path)
        
        # =====================================================================
        # STEP 4: GENERATE SUMMARY (inline, not batched)
        # =====================================================================
        for func_data in enriched_data['functions']:
            summary_prompt = config["prompts"]["summary_prompt"]
            prompt = f"{summary_prompt}"
            if func_data.get('ghidra_code'):
                prompt += f"\n\nGhidra Code:\n```c\n{func_data['ghidra_code']}\n```"
            if func_data.get('asm'):
                prompt += f"\n\nAssembly Instructions:\n{func_data['asm'][:2000]}"
            
            func_data['function_summary'] = llm_interface.generate(prompt)
        
        with print_lock:
            print(f"[STREAM] {task_id} ({lang}) summary ✓", flush=True)
        
        # =====================================================================
        # STEP 5: VEXHELIX OPTIMIZATION LOOP
        # =====================================================================
        for func_data in enriched_data['functions']:
            optimization_success, optimized_code, stats = get_optimized_code_v6(
                c_code=func_data['ghidra_code'],
                function_summary=func_data['function_summary'],
                caller_and_callee_summary=gen_context_summary(enriched_data['callgraph']),
                function_sog="",
                language=lang,
                llm_interface=llm_interface,
                original_binary_path=Path(enriched_data['original_binary_path']),
                function_name=func_data['f_name'],
                original_asm=func_data.get('asm', ''),
                original_ghidra=func_data['ghidra_code'],
                num_args=3,
                task_id=task_id
            )
            
            func_data['optimization_status'] = optimization_success
            func_data['optimized_code'] = optimized_code
            func_data['optimization_stats'] = stats
        
        duration = time.time() - start_time
        final_result = enriched_data['functions'][0].get('optimization_stats', {}).get('final_result', 'unknown') if enriched_data['functions'] else 'no_functions'
        
        with print_lock:
            active_count -= 1
            completed_count += 1
            sym = "✓" if final_result == 'equivalent' else "✗"
            stats = enriched_data['functions'][0].get('optimization_stats', {}) if enriched_data['functions'] else {}
            print(f"[{sym}] {task_id} ({lang}): {final_result} "
                  f"({stats.get('semantic_repair_iterations', 0)}it, "
                  f"{stats.get('vexhelix_calls', 0)}vex, {duration:.1f}s) | "
                  f"done: {completed_count}/{total_tasks}, active: {active_count}", flush=True)
        
        return enriched_data
        
    except Exception as e:
        duration = time.time() - start_time
        with print_lock:
            active_count -= 1
            completed_count += 1
            print(f"[✗] {task_id} ({lang}): exception ({duration:.1f}s) - {str(e)[:100]} | "
                  f"done: {completed_count}/{total_tasks}, active: {active_count}", flush=True)
        return None


def process_batch_streaming(batch_items: List[Dict], temp_base_dir: Path) -> List[Dict]:
    """
    Process a batch with TRUE END-TO-END STREAMING.
    
    Each program flows through the entire pipeline independently:
    Program 1: compile → ghidra → summary → vexhelix (runs immediately!)
    Program 2: compile → ghidra → summary → vexhelix (as soon as worker available)
    
    This eliminates the bottleneck of waiting for ALL compilations, then ALL ghidra, etc.
    """
    global active_count, completed_count, total_tasks
    
    # Reset counters
    active_count = 0
    completed_count = 0
    total_tasks = len(batch_items)
    
    print(f"\n{'='*70}")
    print(f"[STREAMING PIPELINE] Starting TRUE end-to-end streaming")
    print(f"[STREAMING PIPELINE] Programs: {total_tasks}")
    print(f"[STREAMING PIPELINE] Concurrent workers: {PARALLEL_REPAIR_WORKERS}")
    print(f"[STREAMING PIPELINE] Each program: compile → ghidra → summary → vexhelix (independent)")
    print(f"{'='*70}\n")
    
    # Pre-resolve script paths once
    cfg_script = Path(__file__).resolve().parent.parent / "src" / "scripts" / "batched_cfg_extractor.py"
    callgraph_script = Path(__file__).resolve().parent.parent / "src" / "scripts" / "batched_call_graph_extractor.py"
    
    results = []
    
    # TRUE STREAMING: each program runs through entire pipeline independently
    with ThreadPoolExecutor(max_workers=PARALLEL_REPAIR_WORKERS) as executor:
        futures = {
            executor.submit(
                process_single_program_streaming, 
                item, 
                temp_base_dir,
                cfg_script,
                callgraph_script
            ): item
            for item in batch_items
        }
        
        for future in as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
            except Exception as e:
                item = futures[future]
                print(f"[ERROR] Program {item.get('index', '?')} future exception: {e}", flush=True)
    
    # Print summary
    equivalent_count = sum(1 for r in results 
                          if r['functions'] and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    
    c_results = [r for r in results if r.get('language') == 'c']
    cpp_results = [r for r in results if r.get('language') == 'cpp']
    c_equiv = sum(1 for r in c_results 
                  if r['functions'] and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    cpp_equiv = sum(1 for r in cpp_results 
                    if r['functions'] and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    
    print(f"\n{'='*70}")
    print(f"[STREAMING PIPELINE] Complete!")
    print(f"{'='*70}")
    print(f"  Successful: {len(results)}/{total_tasks}")
    print(f"  Equivalent: {equivalent_count}/{len(results)} ({100*equivalent_count/len(results) if results else 0:.0f}%)")
    print(f"    C:   {c_equiv}/{len(c_results)}")
    print(f"    C++: {cpp_equiv}/{len(cpp_results)}")
    print(f"{'='*70}\n")
    
    return results


# =============================================================================
# LEGACY BATCH PROCESSING PIPELINE (kept for reference)
# =============================================================================

def process_batch(batch_items: List[Dict], temp_base_dir: Path) -> List[Dict]:
    """
    Process a batch of items - NOW USES PIPELINED ARCHITECTURE.
    
    Change this to switch between processing modes:
    - process_batch_pipelined: TRUE CPU-style pipeline (recommended)
    - process_batch_streaming: Per-program parallelism
    """
    # Use the new PIPELINED architecture for maximum throughput
    return process_batch_pipelined(batch_items, temp_base_dir)


def process_batch_legacy(batch_items: List[Dict], temp_base_dir: Path) -> List[Dict]:
    """
    LEGACY: Process a batch with separate stages (compile ALL → ghidra ALL → etc.)
    Kept for reference. Use process_batch_streaming for true parallelism.
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
    Process the humaneval decompile json file with TRUE PIPELINED architecture.
    
    NO MORE BATCH LOOPS! All items flow through the pipeline at once.
    Each stage controls its own parallelism:
      COMPILE (20) → GHIDRA (8) → SUMMARY (12) → VEXHELIX (12)
    
    This means while item 1 is in VEXHELIX, item 25 can be in COMPILE!
    
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
    
    # Add index to each item for tracking
    for i, item in enumerate(humaneval_data):
        item['index'] = start_index + i
    
    # Count languages
    c_count = sum(1 for d in humaneval_data if d['language'] == 'c')
    cpp_count = sum(1 for d in humaneval_data if d['language'] == 'cpp')
    
    print(f"\n{'='*70}")
    print(f"MissionDecompile V6 - TRUE PIPELINED Architecture")
    print(f"{'='*70}")
    print(f"Processing {len(humaneval_data)} functions (ALL AT ONCE through pipeline)")
    print(f"  - C programs: {c_count}")
    print(f"  - C++ programs: {cpp_count}")
    print(f"VexHelix API: {VEXHELIX_API_URL}")
    print(f"Pipeline stage widths:")
    print(f"  COMPILE:  {PIPELINE_COMPILE_WIDTH} workers")
    print(f"  GHIDRA:   {PIPELINE_GHIDRA_WIDTH} workers")
    print(f"  SUMMARY:  {PIPELINE_SUMMARY_WIDTH} workers (LLM)")
    print(f"  VEXHELIX: {PIPELINE_VEXHELIX_WIDTH} workers (LLM repair loop)")
    print(f"{'='*70}\n")
    
    with tempfile.TemporaryDirectory() as temp_base_dir:
        temp_base_path = Path(temp_base_dir)
        
        # NO BATCH LOOP! Feed ALL items into the pipeline at once
        # The pipeline stages control parallelism internally
        all_results = process_batch(humaneval_data, temp_base_path)
        
        if all_results:
            save_results(all_results, output_file_path)
            print(f"\n[Save] Saved {len(all_results)} results")
    
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
