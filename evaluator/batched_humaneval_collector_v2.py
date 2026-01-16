"""
Batched HumanEval Collector V2 - Enhanced with D-Helix Semantic Verification

This module extends the original batched collector with:
- Static repair (ensure compilation)
- Semantic verification via D-Helix API (ensure logical correctness)
- Semantic repair loop when D-Helix detects SAT (logical bugs)

Pipeline:
1. Batch compilation of original code
2. Batch Ghidra analysis (CFG + call graphs)
3. Enhanced repair loop (max 15 iterations):
   - Phase 1: Static Repair (fix compilation errors)
   - Phase 2: Semantic Verification (D-Helix API)
   - Phase 3: Semantic Repair (fix logical bugs if SAT)
"""

import yaml
from pathlib import Path
import shutil
import tempfile
import os
import sys
from typing import Tuple, List, Dict, Optional
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import time
from dataclasses import dataclass
import requests

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

# Batching configuration
COMPILATION_BATCH_SIZE = 20
GHIDRA_BATCH_SIZE = 12
LLM_BATCH_SIZE = 16

# D-Helix API configuration
DHELIX_API_URL = "http://127.0.0.1:10012"
DHELIX_TIMEOUT = 120  # seconds

# Repair configuration
MAX_REPAIR_ITERATIONS = 15  # Total iterations including static + semantic repair
MAX_STATIC_REPAIR_PER_CYCLE = 3  # Max static repair attempts before checking semantics


@dataclass
class DHelixResult:
    """Result from D-Helix verification."""
    success: bool
    result: Optional[str]  # "sat" or "unsat"
    z3_formula: Optional[str]
    counterexample: Optional[Dict]
    error_message: Optional[str]


def call_dhelix_api(binary_path: Path, decompiled_code: str, function_name: str) -> DHelixResult:
    """
    Call D-Helix API to verify semantic equivalence between binary and decompiled code.
    
    Returns:
        DHelixResult with verification outcome
    """
    try:
        print(f"[D-Helix] Verifying {function_name} against binary {binary_path}...")
        
        with open(binary_path, 'rb') as binary_file:
            files = {
                'binary': (binary_path.name, binary_file, 'application/octet-stream'),
                'decompiled_code': (f'{function_name}.c', decompiled_code, 'text/plain')
            }
            data = {
                'function_name': function_name
            }
            
            response = requests.post(
                f"{DHELIX_API_URL}/verify",
                files=files,
                data=data,
                timeout=DHELIX_TIMEOUT
            )
        
        if response.status_code == 200:
            result = response.json()
            print(f"[D-Helix] Result: {result['result']} ({result['status']})")
            
            return DHelixResult(
                success=True,
                result=result['result'],
                z3_formula=result.get('z3_formula'),
                counterexample=result.get('counterexample'),
                error_message=None
            )
        else:
            error_msg = f"HTTP {response.status_code}: {response.text}"
            print(f"[D-Helix] Error: {error_msg}")
            return DHelixResult(
                success=False,
                result=None,
                z3_formula=None,
                counterexample=None,
                error_message=error_msg
            )
    
    except requests.exceptions.Timeout:
        print(f"[D-Helix] Timeout after {DHELIX_TIMEOUT}s")
        return DHelixResult(
            success=False,
            result=None,
            z3_formula=None,
            counterexample=None,
            error_message=f"Timeout after {DHELIX_TIMEOUT}s"
        )
    except Exception as e:
        print(f"[D-Helix] Exception: {e}")
        return DHelixResult(
            success=False,
            result=None,
            z3_formula=None,
            counterexample=None,
            error_message=str(e)
        )


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
    prompt = f"{repair_prompt}\n\n```c\nLanguage:{language}\nSummary:{function_summary}\nCode:{c_code}\n```\n\nCompilation Errors:\n{compilation_errors}\n\nPlease provide the corrected C code."
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
    dhelix_result: DHelixResult,
    language: str
) -> str:
    """
    Generate semantic repair prompt using D-Helix verification results.
    """
    semantic_prompt = config["prompts"]["semantic_repair"]
    
    prompt = f"{semantic_prompt}\n\n"
    
    # Add context
    prompt += f"Language: {language}\n\n"
    
    prompt += f"Original Assembly Code:\n```asm\n{original_asm}\n```\n\n"
    
    prompt += f"Original Ghidra Decompilation:\n```c\n{original_ghidra}\n```\n\n"
    
    prompt += f"Current Decompiled Code (INCORRECT):\n```c\n{current_code}\n```\n\n"
    
    prompt += f"Function Summary:\n{function_summary}\n\n"
    
    prompt += f"D-Helix Verification Result: SAT (semantic mismatch detected)\n\n"
    
    # Add counterexample if available
    if dhelix_result.counterexample:
        prompt += f"Counterexample (input values that expose the bug):\n"
        prompt += json.dumps(dhelix_result.counterexample, indent=2)
        prompt += "\n\n"
    
    # Add partial Z3 formula if available (truncate to avoid context overflow)
    if dhelix_result.z3_formula:
        formula_preview = dhelix_result.z3_formula[:500]
        if len(dhelix_result.z3_formula) > 500:
            formula_preview += "\n... (truncated)"
        prompt += f"Z3 Formula (partial):\n{formula_preview}\n\n"
    
    prompt += "Please provide the corrected function that fixes the logical bug.\n"
    
    return prompt


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


def get_optimized_code_v2(
    c_code: str,
    function_summary: str,
    caller_and_callee_summary: str,
    function_sog: str,
    language: str,
    llm_interface: LLMInterface,
    original_binary_path: Path,
    function_name: str,
    original_asm: str,
    original_ghidra: str
) -> Tuple[bool, str, Dict]:
    """
    Enhanced optimization with D-Helix semantic verification.
    
    Returns:
        (success, optimized_code, stats)
    """
    stats = {
        'static_repair_iterations': 0,
        'semantic_repair_iterations': 0,
        'dhelix_calls': 0,
        'dhelix_unsat_achieved': False,
        'final_result': None
    }
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Initial LLM prompt
        print(f"[Optimize V2] Starting optimization for {function_name}...")
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
            print(f"\n[Optimize V2] === Iteration {iteration + 1}/{MAX_REPAIR_ITERATIONS} ===")
            
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
            
            # Phase 2: Semantic Verification (D-Helix)
            # NOTE: D-Helix only supports C code, not C++ (uses clang, not clang++)
            if language == "cpp":
                print(f"[Semantic Verify] Skipping D-Helix for C++ code (not supported)")
                stats['final_result'] = 'cpp_skipped'
                return True, optimized_code, stats
            
            print(f"[Semantic Verify] Calling D-Helix API...")
            stats['dhelix_calls'] += 1
            
            dhelix_result = call_dhelix_api(
                binary_path=original_binary_path,
                decompiled_code=optimized_code,
                function_name=function_name
            )
            
            if not dhelix_result.success:
                print(f"[Semantic Verify] D-Helix API failed: {dhelix_result.error_message}")
                print(f"[Semantic Verify] Cannot verify semantics, returning compilable code")
                stats['final_result'] = 'dhelix_error'
                return True, optimized_code, stats
            
            if dhelix_result.result == "unsat":
                print(f"[Semantic Verify] ✓✓✓ UNSAT - Code is semantically equivalent!")
                stats['dhelix_unsat_achieved'] = True
                stats['final_result'] = 'unsat'
                return True, optimized_code, stats
            
            # Phase 3: Semantic Repair (fix logical bugs)
            print(f"[Semantic Verify] ✗ SAT - Logical bug detected")
            print(f"[Semantic Repair] Attempting to fix logical errors...")
            stats['semantic_repair_iterations'] += 1
            
            semantic_prompt = get_semantic_repair_prompt(
                original_asm=original_asm,
                original_ghidra=original_ghidra,
                current_code=optimized_code,
                function_summary=function_summary,
                dhelix_result=dhelix_result,
                language=language
            )
            
            optimized_code = llm_interface.generate(semantic_prompt)
            print(f"[Semantic Repair] Received semantically repaired code from LLM")
            # Loop will now re-check compilation and semantics
        
        # Max iterations reached
        print(f"[Optimize V2] Max iterations ({MAX_REPAIR_ITERATIONS}) reached")
        
        # Do final check
        compile_success, _, _ = compile_code(optimized_code, language, temp_path)
        
        if compile_success:
            stats['final_result'] = 'max_iterations_compilable'
            return True, optimized_code, stats
        else:
            stats['final_result'] = 'max_iterations_not_compilable'
            return False, optimized_code, stats


@dataclass
class CompilationResult:
    """Result of compiling a single program."""
    index: int
    success: bool
    executable_path: Optional[Path]
    error_message: Optional[str]
    data: Dict


def create_cfg_output_dir(executable_name: str) -> Path:
    """Create output directory for CFG extraction."""
    output_dir_path = Path(config["humaneval"]["output_path"]) / "SOG" / executable_name
    if output_dir_path.exists():
        shutil.rmtree(output_dir_path)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    return output_dir_path


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
            print(f"[Compile] Failed for index {data['index']}: {message}")
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
                print(f"[Batch Compile] ✓ Index {result.index} compiled successfully")
            else:
                print(f"[Batch Compile] ✗ Index {result.index} failed")
    
    successful = sum(1 for r in results if r.success)
    print(f"[Batch Compile] Completed: {successful}/{len(items)} successful\n")
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
    output_dir = create_cfg_output_dir(executable_name)
    
    cfg_map = g.extract_cfg(exe_path, output_dir)
    callgraph_map = g.extract_call_graph(exe_path, output_dir)
    
    return {
        'cfg_map': cfg_map,
        'callgraph_map': callgraph_map,
        'output_dir': output_dir,
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
    program_data['original_binary_path'] = str(original_binary_path)  # Store for D-Helix

    program_data['functions'] = []
    
    cfg_map = ghidra_result['cfg_map']
    callgraph_map = ghidra_result['callgraph_map']
    
    # Build call graph if available
    if 'call_graph' in callgraph_map and callgraph_map['call_graph']:
        callgraph = build_call_graph(callgraph_map['call_graph'])
        sorted_functions = topological_sort(callgraph)
    else:
        # No call graph available, use default
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
                sog_dot = f.read()
        else:
            f_data['sog_dot'] = ""
        
        callers = [caller for caller, callees in callgraph.items() if function_name in callees]
        callees = callgraph.get(function_name, [])
        f_data['callers'] = callers
        f_data['callees'] = callees
        
        functions.append(f_data)
    
    program_data['functions'] = functions
    return program_data


def batch_optimize_functions_v2(enriched_programs: List[Dict]) -> List[Dict]:
    """
    Optimize multiple functions using batched LLM calls with D-Helix verification.
    """
    print(f"\n[Batch Optimize V2] Starting optimization of {len(enriched_programs)} programs...")
    
    # Step 1: Batch generate summaries
    summary_prompts = []
    for prog_idx, prog_data in enumerate(enriched_programs):
        for func_data in prog_data['functions']:
            summary_prompt = config["prompts"]["summary_prompt"]
            prompt = f"{summary_prompt}"
            if func_data.get('ghidra_code'):
                prompt += f"\n\nGhidra Code:\n```c\n{func_data['ghidra_code']}\n```"
            if func_data.get('asm'):
                prompt += f"\n\nAssembly Instructions:\n{func_data['asm']}"
            summary_prompts.append((prog_idx, prompt))
    
    summaries = gen_code_summary_batch(summary_prompts)
    
    # Step 2: Add summaries to function data
    for prog_idx, prog_data in enumerate(enriched_programs):
        for func_data in prog_data['functions']:
            func_data['function_summary'] = summaries.get(prog_idx, "")
    
    # Step 3: Optimize with D-Helix verification (sequential due to complexity)
    for prog_idx, prog_data in enumerate(enriched_programs):
        for func_data in prog_data['functions']:
            print(f"\n[Batch Optimize V2] Processing function {func_data['f_name']} in program {prog_idx}...")
            
            optimization_success, optimized_code, stats = get_optimized_code_v2(
                c_code=func_data['ghidra_code'],
                function_summary=func_data['function_summary'],
                caller_and_callee_summary=gen_context_summary(prog_data['callgraph']),
                function_sog="",
                language=prog_data.get('language', 'c'),
                llm_interface=llm_interface,
                original_binary_path=Path(prog_data['original_binary_path']),
                function_name=func_data['f_name'],
                original_asm=func_data.get('asm', ''),
                original_ghidra=func_data['ghidra_code']
            )
            
            func_data['optimization_status'] = optimization_success
            func_data['optimized_code'] = optimized_code
            func_data['optimization_stats'] = stats
            
            print(f"[Batch Optimize V2] Stats for {func_data['f_name']}:")
            print(f"  - Static repairs: {stats['static_repair_iterations']}")
            print(f"  - Semantic repairs: {stats['semantic_repair_iterations']}")
            print(f"  - D-Helix calls: {stats['dhelix_calls']}")
            print(f"  - UNSAT achieved: {stats['dhelix_unsat_achieved']}")
            print(f"  - Final result: {stats['final_result']}")
    
    print(f"[Batch Optimize V2] Completed optimization\n")
    return enriched_programs


def process_batch(batch_items: List[Dict], temp_base_dir: Path) -> List[Dict]:
    """
    Process a batch of items through the entire pipeline with D-Helix verification.
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
    
    # Step 4: Batch LLM optimization with D-Helix verification
    optimized_programs = batch_optimize_functions_v2(enriched_programs)
    
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


def process_humaneval_decompile(json_path: Path) -> List[Dict]:
    """
    Process the humaneval decompile json file with batched operations and D-Helix verification.
    """
    output_file_path = output_dir / "batched_enriched_humaneval_decompile_v2.json"
    output_file_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(json_path, "r") as f:
        humaneval_data = json.load(f)
    
    print(f"\n{'='*60}")
    print(f"Processing {len(humaneval_data)} functions from HumanEval dataset")
    print(f"D-Helix Semantic Verification ENABLED")
    print(f"{'='*60}\n")
    
    with tempfile.TemporaryDirectory() as temp_base_dir:
        temp_base_path = Path(temp_base_dir)
        
        batch_size = COMPILATION_BATCH_SIZE
        total_batches = (len(humaneval_data) + batch_size - 1) // batch_size
        
        for batch_idx in range(0, len(humaneval_data), batch_size):
            batch_num = batch_idx // batch_size + 1
            batch_items = humaneval_data[batch_idx:batch_idx + batch_size]
            
            print(f"\n{'='*60}")
            print(f"BATCH {batch_num}/{total_batches}: Processing items {batch_idx} to {batch_idx + len(batch_items) - 1}")
            print(f"{'='*60}\n")
            
            batch_results = process_batch(batch_items, temp_base_path)
            
            if batch_results:
                save_results(batch_results, output_file_path)
                print(f"\n[Save] Saved {len(batch_results)} results from batch {batch_num}")
    
    print(f"\n{'='*60}")
    print(f"Processing complete! Results saved to {output_file_path}")
    print(f"{'='*60}\n")


def main():
    """Main entry point."""
    json_path = corpus_path / "humaneval-decompile.json"
    
    # Check if D-Helix API is reachable
    try:
        response = requests.get(f"{DHELIX_API_URL}/health", timeout=5)
        if response.status_code == 200:
            print(f"✓ D-Helix API is reachable at {DHELIX_API_URL}")
        else:
            print(f"⚠ D-Helix API returned unexpected status: {response.status_code}")
    except Exception as e:
        print(f"⚠ Warning: Cannot reach D-Helix API at {DHELIX_API_URL}")
        print(f"  Error: {e}")
        print(f"  Continuing anyway, but semantic verification will fail...")
    
    process_humaneval_decompile(json_path)


if __name__ == "__main__":
    main()
