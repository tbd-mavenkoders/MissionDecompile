"""
Batched HumanEval Collector - Optimized for Parallel Processing

This module processes HumanEval decompiled code with optimizations for:
- Parallel compilation of multiple programs
- Batch Ghidra analysis (CFG and call graph extraction)
- Batched LLM inference (up to 8 concurrent requests)
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

# Batching configuration optimized for system resources
# System: 24 CPU cores, 188GB RAM available
COMPILATION_BATCH_SIZE = 20  # Compile 20 programs in parallel (lightweight, CPU-bound)
GHIDRA_BATCH_SIZE = 12  # Process 12 executables in Ghidra at once (memory-intensive, ~15GB per instance)
LLM_BATCH_SIZE = 8  # Send 8 LLM requests in parallel (hardware constraint)


def get_initial_prompt(c_code: str, function_summary: str, caller_and_callee_summary: str, function_sog: str, language: str) -> str:
    """
    Generate the initial prompt for the repair tool given C code of the particular function.
    """
    initial_prompt = config["prompts"]["system_prompt"]
    prompt = f"{initial_prompt}\n\n```Language:{language}\nSummary:{function_summary}\n{c_code}\n```"
    if caller_and_callee_summary:
        prompt += f"\n\nCaller and Callee Summary:\n{caller_and_callee_summary}"
    if function_sog:
        prompt += f"\n\nFunction SOG:\n{function_sog}"
    return prompt


def get_repair_prompt(c_code: str, compilation_errors: str, function_summary: str, caller_and_callee_summary: str, function_sog: str, language: str) -> str:
    """
    Generate the repair prompt for the repair tool given C code of the particular function and compilation errors.
    """
    repair_prompt = config["prompts"]["compilation_error"]
    prompt = f"{repair_prompt}\n\n```c\nLanguage:{language}\nSummary:{function_summary}\nCode:{c_code}\n```\n\nCompilation Errors:\n{compilation_errors}\n\nPlease provide the corrected C code."
    if caller_and_callee_summary:
        prompt += f"\n\nCaller and Callee Summary:\n{caller_and_callee_summary}"
    if function_sog:
        prompt += f"\n\nFunction SOG:\n{function_sog}"
    return prompt


def get_optimized_code(c_code: str, function_summary: str, caller_and_callee_summary: str, function_sog: str, language: str, max_iterations: int, llm_interface: LLMInterface, c_flag: bool) -> Tuple[bool, str]:
    """
    Generate optimized C code using LLM for the given original C code file.
    """
    
    # handle everything in a temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        # write the original code to a file with correct extension
        file_extension = "cpp" if language == "cpp" else "c"
        original_c_file = Path(temp_dir) / f"original.{file_extension}"
        with open(original_c_file, "w") as f:
            f.write(c_code)
        
        # if not, provide an initial LLM optimization
        print("Original Ghidra Code does not compile. Starting optimization...")
        initial_prompt = get_initial_prompt(
            c_code=c_code,
            function_summary=function_summary,
            caller_and_callee_summary=caller_and_callee_summary,
            function_sog=function_sog,
            language=language
        )
        
        optimized_code = llm_interface.generate(initial_prompt)
        
        # check if initially prompted code compiles
        original_c_file.write_text(optimized_code)
        status, message = c.compile_source(
            source_file_path=original_c_file,
            output_file_path=Path(temp_dir) / "optimized.out",
            opt=OptimizationLevel.O0,
            is_cpp=(language == "cpp"),
            c_flag=c_flag
        )
        
        if status:
            print("Optimized code compiles successfully after initial LLM prompt.")
            return True, optimized_code
        
        # begin static repair loop
        for iteration in range(max_iterations):
            print(f"Static Repair Iteration {iteration + 1}...")
            
            # acquire optimized output through error passing
            e = ErrorNormalizer()
            error_prompt = e.format_for_llm(message)
            print("Compilation Errors:\n", error_prompt)
            repair_prompt = get_repair_prompt(
                c_code=optimized_code,
                compilation_errors=error_prompt,
                function_summary=function_summary,
                caller_and_callee_summary=caller_and_callee_summary,
                function_sog=function_sog,
                language=language
            )
            optimized_code = llm_interface.generate(repair_prompt)
            print("Received Optimized Code from LLM.")
            print(optimized_code)
            
            # check if it compiles
            original_c_file.write_text(optimized_code)
            status, message = c.compile_source(
                source_file_path=original_c_file,
                output_file_path=Path(temp_dir) / "optimized.out",
                opt=OptimizationLevel.O0,
                is_cpp=(language == "cpp"),
                c_flag=c_flag
            )
            
            if status:
                print(f"Optimized code compiles successfully after {iteration + 1} iterations.")
                return True, optimized_code
            else:
                print(f"Optimized code still does not compile after iteration {iteration + 1}. Continuing...")
        
        print("Max optimization iterations reached. Returning last optimized code.")
        return False, optimized_code


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
    output_dir_path = Path(config["paths"]["output_path"]) / "SOG" / executable_name
    if output_dir_path.exists():
        shutil.rmtree(output_dir_path)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    return output_dir_path


def compile_single_program(data: Dict, temp_base_dir: Path) -> CompilationResult:
    """Compile a single program and return the result."""
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
    """
    Run Ghidra analysis on multiple executables in batch.
    Returns a mapping of index -> {cfg_map, callgraph_map}
    """
    print(f"\n[Batch Ghidra] Starting analysis of {len(executables)} executables...")
    results = {}
    
    # Prepare Ghidra batch script paths
    cfg_script = Path(__file__).resolve().parent.parent / "src" / "scripts" / "batched_cfg_extractor.py"
    callgraph_script = Path(__file__).resolve().parent.parent / "src" / "scripts" / "batched_call_graph_extractor.py"
    
    # Process executables in batches
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
    
    # Extract CFG and call graph using Ghidra
    cfg_map = g.extract_cfg(exe_path, output_dir)
    callgraph_map = g.extract_call_graph(exe_path, output_dir)
    
    return {
        'cfg_map': cfg_map,
        'callgraph_map': callgraph_map,
        'output_dir': output_dir,
        'executable_name': executable_name
    }


def gen_code_summary_batch(prompts: List[Tuple[int, str]]) -> Dict[int, str]:
    """
    Generate code summaries for multiple functions in batch.
    Returns a mapping of index -> summary.
    """
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


def gen_code_summary(asm: str, ghidra: str) -> str:
    """Generate a single code summary (for compatibility)."""
    summary_prompt = config["prompts"]["summary_prompt"]
    prompt = f"{summary_prompt}"
    if ghidra:
        prompt += f"\n\nGhidra Code:\n```c\n{ghidra}\n```"
    if asm:
        prompt += f"\n\nAssembly Instructions:\n{asm}"
    
    response = llm_interface.generate(prompt)
    return response


def split_enrichment(data: Dict, ghidra_result: Dict) -> Dict:
    """
    Enrich function data using pre-extracted Ghidra analysis.
    """
    program_data = {}
    program_data['executable_name'] = ghidra_result['executable_name']
    program_data['test'] = data['test']
    program_data['func_dep'] = data['func_dep']

    program_data['functions'] = []
    
    cfg_map = ghidra_result['cfg_map']
    callgraph_map = ghidra_result['callgraph_map']
    
    # Build and sort call graph
    callgraph = build_call_graph(callgraph_map.get('call_graph', {}))
    sorted_functions = topological_sort(callgraph)
    
    # Add func0 if not present
    if len(sorted_functions) == 0:
        sorted_functions.append("func0")
    
    program_data['callgraph'] = callgraph
    
    # Process functions
    functions = []
    for function_name in sorted_functions:
        if function_name != "func0":
            continue
        
        f_data = {}
        f_data['f_name'] = function_name
        f_data['asm'] = data['asm']
        f_data['ghidra_code'] = data['ghidra_pseudo']
        
        # Get SOG
        sog_path = cfg_map.get(function_name)
        if sog_path:
            with open(sog_path, 'r') as f:
                sog_dot = f.read()
            f_data['sog_dot'] = json.loads(sog_dot)
        else:
            f_data['sog_dot'] = ""
        
        # Get caller and callee context
        callers = [caller for caller, callees in callgraph.items() if function_name in callees]
        callees = callgraph.get(function_name, [])
        f_data['callers'] = callers
        f_data['callees'] = callees
        
        functions.append(f_data)
    
    program_data['functions'] = functions
    return program_data


def batch_optimize_functions(enriched_programs: List[Dict]) -> List[Dict]:
    """
    Optimize multiple functions using batched LLM calls.
    """
    print(f"\n[Batch Optimize] Starting optimization of {len(enriched_programs)} programs...")
    
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
    
    # Generate all summaries in batch
    summaries = gen_code_summary_batch(summary_prompts)
    
    # Step 2: Add summaries to function data
    for prog_idx, prog_data in enumerate(enriched_programs):
        for func_data in prog_data['functions']:
            func_data['function_summary'] = summaries.get(prog_idx, "")
    
    # Step 3: Batch optimize code (using get_optimized_code)
    # Note: get_optimized_code may involve multiple iterations, so we still call it per function
    # but we can batch the initial LLM calls
    
    for prog_idx, prog_data in enumerate(enriched_programs):
        for func_data in prog_data['functions']:
            print(f"[Batch Optimize] Optimizing function {func_data['f_name']} in program {prog_idx}...")
            func_data['optimization_status'], func_data['optimized_code'] = get_optimized_code(
                c_code=func_data['ghidra_code'],
                function_summary=func_data['function_summary'],
                caller_and_callee_summary="",
                function_sog=func_data['sog_dot'],
                language=prog_data.get('language', 'c'),
                llm_interface=llm_interface,
                max_iterations=3,
                c_flag=True
            )
    
    print(f"[Batch Optimize] Completed optimization\n")
    return enriched_programs


def process_batch(batch_items: List[Dict], temp_base_dir: Path) -> List[Dict]:
    """
    Process a batch of items through the entire pipeline:
    1. Parallel compilation
    2. Batch Ghidra analysis
    3. Batch LLM optimization
    """
    # Step 1: Compile all programs in parallel
    compile_results = batch_compile_programs(batch_items, temp_base_dir)
    
    # Filter successful compilations
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
        
        enriched_data = split_enrichment(compile_result.data, ghidra_result)
        enriched_data['index'] = compile_result.data['index']
        enriched_data['language'] = compile_result.data['language']
        enriched_programs.append(enriched_data)
    
    # Step 4: Batch LLM optimization
    optimized_programs = batch_optimize_functions(enriched_programs)
    
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
    Process the humaneval decompile json file with batched operations.
    """
    output_file_path = output_dir / "batched_enriched_humaneval_decompile.json"
    output_file_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(json_path, "r") as f:
        humaneval_data = json.load(f)
    
    print(f"\n{'='*60}")
    print(f"Processing {len(humaneval_data)} functions from HumanEval dataset")
    print(f"{'='*60}\n")
    
    # Create a persistent temp directory for this run
    with tempfile.TemporaryDirectory() as temp_base_dir:
        temp_base_path = Path(temp_base_dir)
        
        # Process in batches
        batch_size = COMPILATION_BATCH_SIZE
        total_batches = (len(humaneval_data) + batch_size - 1) // batch_size
        
        for batch_idx in range(0, len(humaneval_data), batch_size):
            batch_num = batch_idx // batch_size + 1
            batch_items = humaneval_data[batch_idx:batch_idx + batch_size]
            
            print(f"\n{'='*60}")
            print(f"BATCH {batch_num}/{total_batches}: Processing items {batch_idx} to {batch_idx + len(batch_items) - 1}")
            print(f"{'='*60}\n")
            
            batch_results = process_batch(batch_items, temp_base_path)
            
            # Save results incrementally
            if batch_results:
                save_results(batch_results, output_file_path)
                print(f"\n[Save] Saved {len(batch_results)} results from batch {batch_num}")
    
    print(f"\n{'='*60}")
    print(f"Processing complete! Results saved to {output_file_path}")
    print(f"{'='*60}\n")


def main():
    """Main entry point."""
    json_path = corpus_path / "humaneval-decompile.json"
    process_humaneval_decompile(json_path)


if __name__ == "__main__":
    main()
