"""
Batched HumanEval Re-evaluation - Optimized for Parallel Processing

This module re-evaluates optimized HumanEval code with parallelism for:
- Parallel compilation and execution of multiple programs
- Batched LLM inference for error analysis (up to 8 concurrent requests)
- Incremental statistics tracking and result saving
"""

import yaml
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.compile import Compiler, OptimizationLevel
from utils.llm_interface import create_llm_interface
import tempfile
import subprocess
from typing import Tuple, List, Dict, Optional
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import threading

c = Compiler()

# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
print(f"Loading config from: {CONFIG_PATH}")

with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

corpus_path = Path(config["humaneval"]["corpus_path"])
output_path = Path(config["humaneval"]["output_path"])

llm_interface = create_llm_interface(
    provider=config["llm"]["vllm_provider"],
    model_name=config["llm"]["vllm_model_name"],
    base_url=config["llm"]["vllm_base_url"]
)

# Batching configuration optimized for system resources
COMPILATION_BATCH_SIZE = 20  # Compile 20 programs in parallel (lightweight, CPU-bound)
LLM_BATCH_SIZE = 8  # Send 8 LLM requests in parallel (hardware constraint)


@dataclass
class ExecutionResult:
    """Result of compiling and executing a single program."""
    index: int
    opt: str
    compiled: bool
    executed: bool
    message: str
    log: Optional[Dict]


class StatsTracker:
    """Thread-safe statistics tracker."""
    def __init__(self):
        self.stats = {}
        self.lock = threading.Lock()
    
    def ensure_opt_level(self, opt: str):
        """Ensure optimization level exists in stats."""
        with self.lock:
            if opt not in self.stats:
                self.stats[opt] = {
                    "total": 0,
                    "compilation_failures": 0,
                    "execution_failures": 0,
                    "successful_executions": 0
                }
    
    def increment(self, opt: str, key: str):
        """Increment a counter for a specific optimization level."""
        with self.lock:
            self.stats[opt][key] += 1
    
    def get_stats(self) -> Dict:
        """Get a copy of current statistics."""
        with self.lock:
            return dict(self.stats)
    
    def print_stats(self):
        """Print statistics for all optimization levels."""
        stats_copy = self.get_stats()
        print("\n" + "="*60)
        print("CURRENT STATISTICS")
        print("="*60)
        
        for opt_level, opt_stats in stats_copy.items():
            total_opt = opt_stats["total"]
            c_fail_opt = opt_stats["compilation_failures"]
            e_fail_opt = opt_stats["execution_failures"]
            ce_success_opt = opt_stats["successful_executions"]
            
            if total_opt > 0:
                success_rate = (ce_success_opt / total_opt) * 100
                print(f"\nOptimization Level: {opt_level}")
                print(f"  Total: {total_opt}")
                print(f"  Compilation failures: {c_fail_opt}")
                print(f"  Execution failures: {e_fail_opt}")
                print(f"  Successful executions: {ce_success_opt}")
                print(f"  Success Rate: {success_rate:.2f}%")
        
        # Calculate average success rate
        if stats_copy:
            avg_rate = sum(
                (opt_stats["successful_executions"] / opt_stats["total"] * 100)
                for opt_stats in stats_copy.values()
                if opt_stats["total"] > 0
            ) / len([s for s in stats_copy.values() if s["total"] > 0])
            print(f"\nAverage Success Rate: {avg_rate:.2f}%")
        
        print("="*60 + "\n")


def compile_and_execute(c_file_path: Path, language: str) -> Tuple[bool, bool, str]:
    """
    Compile and execute the C code, returning any runtime errors.
    """
    output_executable = c_file_path.with_suffix('')
    status, compile_message = c.compile_source(
        source_file_path=c_file_path,
        output_file_path=output_executable,
        opt=OptimizationLevel.O0,
        is_cpp=(language == "cpp"),
        c_flag=False,
        extra_flags=["-lm"]
    )
    
    # if fails to compile, return error
    if not status:
        return False, False, compile_message
    
    # if compiles, run and capture output by running ./output_executable
    try:
        command = [f"./{output_executable.name}"]
        res = subprocess.run(
            command,
            cwd=output_executable.parent,
            capture_output=True,
            text=True,
            timeout=5
        )
        if res.returncode == 0:
            return True, True, res.stdout
        else:
            return True, False, res.stderr
    except subprocess.TimeoutExpired:
        return True, False, "Execution timeout (5 seconds)"
    except Exception as e:
        return True, False, str(e)


def process_single_program(data: Dict, output_data: Dict, stats: StatsTracker) -> ExecutionResult:
    """Process a single program: compile, execute, and track results."""
    try:
        corpus_index = data["index"]
        optimized_code = ""
        ghidra_code = ""
        c_include = ""
        
        # Extract optimized code
        for function in output_data["functions"]:
            if function["f_name"] == "func0" and function["optimization_status"] == True:
                optimized_code = function["optimized_code"]
                ghidra_code = function["ghidra_code"]
                break
        
        test_code = output_data["test"]
        c_include += output_data["func_dep"] + "\n"
        
        # Create log for error analysis
        log = {
            "index": corpus_index,
            "original_code": output_data["original_code"],
            "optimized_code": optimized_code,
            "ghidra_code": ghidra_code,
            "test_code": test_code
        }
        
        opt = output_data["opt"]
        stats.ensure_opt_level(opt)
        
        language = output_data["language"]
        
        # Skip if no optimized code
        if optimized_code == "":
            return ExecutionResult(
                index=corpus_index,
                opt=opt,
                compiled=False,
                executed=False,
                message="No optimized code available",
                log=None
            )
        
        stats.increment(opt, "total")
        
        # Prepare C code
        c_optimized = optimized_code
        c_test = test_code
        
        for line in optimized_code.splitlines():
            if "include" in line:
                c_include += line + "\n"
                c_optimized = c_optimized.replace(line, "")
        
        for line in test_code.splitlines():
            if "include" in line:
                c_include += line + "\n"
                c_test = c_test.replace(line, "")
        
        # Add 'using namespace std' for C++
        if language == "cpp":
            c_include += "using namespace std;\n"
        
        original_c_code = c_include + "\n" + c_optimized + "\n" + c_test
        
        # Compile and execute in temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = Path(temp_dir)
            c_file_path = temp_dir_path / f"temp_code.{'cpp' if language == 'cpp' else 'c'}"
            with open(c_file_path, "w") as f:
                f.write(original_c_code)
            
            compiled, executed, runtime_message = compile_and_execute(c_file_path, language)
            
            if not compiled:
                print(f"[Compile Error] Index {corpus_index}: {runtime_message[:100]}")
                stats.increment(opt, "compilation_failures")
                log["runtime_message"] = runtime_message
                return ExecutionResult(
                    index=corpus_index,
                    opt=opt,
                    compiled=False,
                    executed=False,
                    message=runtime_message,
                    log=log
                )
            elif compiled and executed:
                print(f"[Success] Index {corpus_index}")
                stats.increment(opt, "successful_executions")
                return ExecutionResult(
                    index=corpus_index,
                    opt=opt,
                    compiled=True,
                    executed=True,
                    message=runtime_message,
                    log=None
                )
            else:
                print(f"[Execution Error] Index {corpus_index}: {runtime_message[:100]}")
                stats.increment(opt, "execution_failures")
                log["runtime_message"] = runtime_message
                return ExecutionResult(
                    index=corpus_index,
                    opt=opt,
                    compiled=True,
                    executed=False,
                    message=runtime_message,
                    log=log
                )
    
    except Exception as e:
        print(f"[Exception] Index {data['index']}: {e}")
        return ExecutionResult(
            index=data["index"],
            opt=output_data.get("opt", "unknown"),
            compiled=False,
            executed=False,
            message=str(e),
            log=None
        )


def batch_process_programs(corpus_data: List[Dict], output_data: List[Dict], stats: StatsTracker) -> List[ExecutionResult]:
    """Process multiple programs in parallel."""
    print(f"\n[Batch Process] Starting evaluation of {len(output_data)} programs...")
    results = []
    
    # Create a mapping from index to corpus data for quick lookup
    corpus_map = {item["index"]: item for item in corpus_data}
    
    with ThreadPoolExecutor(max_workers=COMPILATION_BATCH_SIZE) as executor:
        futures = {}
        for output_item in output_data:
            corpus_item = corpus_map.get(output_item["index"], {})
            future = executor.submit(process_single_program, corpus_item, output_item, stats)
            futures[future] = output_item["index"]
        
        for future in as_completed(futures):
            idx = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"[Batch Process] Exception for index {idx}: {e}")
    
    print(f"[Batch Process] Completed evaluation of {len(results)} programs\n")
    return results


def batch_analyze_errors(error_logs: List[Dict]) -> List[Dict]:
    """Analyze errors using batched LLM calls."""
    if not error_logs:
        return []
    
    print(f"\n[Batch LLM] Analyzing {len(error_logs)} errors...")
    analysis_results = []
    
    with ThreadPoolExecutor(max_workers=LLM_BATCH_SIZE) as executor:
        futures = {}
        for log in error_logs:
            prompt = config["prompts"]["analysis_prompt"] + "\n\n" + str(log)
            future = executor.submit(analyze_single_error, log, prompt)
            futures[future] = log["index"]
        
        for future in as_completed(futures):
            idx = futures[future]
            try:
                result = future.result()
                analysis_results.append(result)
                print(f"[Batch LLM] ✓ Error analysis {idx} completed")
            except Exception as e:
                print(f"[Batch LLM] ✗ Error analysis {idx} failed: {e}")
    
    print(f"[Batch LLM] Completed {len(analysis_results)} error analyses\n")
    return analysis_results


def analyze_single_error(log: Dict, prompt: str) -> Dict:
    """Analyze a single error with LLM."""
    try:
        error_analysis = json.loads(llm_interface.generate(prompt))
        error_analysis["original_code"] = log["original_code"]
        error_analysis["optimized_code"] = log["optimized_code"]
        return error_analysis
    except json.JSONDecodeError as e:
        print(f"[LLM] JSON decode error for index {log['index']}: {e}")
        return {
            "index": log["index"],
            "error": "Failed to parse LLM response",
            "original_code": log["original_code"],
            "optimized_code": log["optimized_code"]
        }


def save_analysis_results(analysis_results: List[Dict], analysis_path: Path):
    """Save error analysis results incrementally."""
    if analysis_path.exists():
        with open(analysis_path, "r") as f:
            existing_data = json.load(f)
        existing_data.extend(analysis_results)
        with open(analysis_path, "w") as f:
            json.dump(existing_data, f, indent=4)
    else:
        with open(analysis_path, "w") as f:
            json.dump(analysis_results, f, indent=4)


def process_json_file(corpus_file: Path, output_file: Path) -> Dict:
    """Process the JSON file with batched operations."""
    stats = StatsTracker()
    
    # Load the JSON files
    with open(corpus_file, "r") as f:
        corpus = json.load(f)
    with open(output_file, "r") as out_f:
        output = json.load(out_f)
    
    print(f"\n{'='*60}")
    print(f"Processing {len(output)} programs from HumanEval evaluation")
    print(f"{'='*60}\n")
    
    # Process in batches
    batch_size = COMPILATION_BATCH_SIZE
    total_batches = (len(output) + batch_size - 1) // batch_size
    
    analysis_path = output_path / "analysis_logs.json"
    
    for batch_idx in range(0, len(output), batch_size):
        batch_num = batch_idx // batch_size + 1
        batch_output = output[batch_idx:batch_idx + batch_size]
        
        print(f"\n{'='*60}")
        print(f"BATCH {batch_num}/{total_batches}: Processing items {batch_idx} to {batch_idx + len(batch_output) - 1}")
        print(f"{'='*60}\n")
        
        # Batch process programs
        batch_results = batch_process_programs(corpus, batch_output, stats)
        
        # Collect error logs that need analysis
        error_logs = [result.log for result in batch_results if result.log is not None]
        
        # Batch analyze errors
        if error_logs:
            analysis_results = batch_analyze_errors(error_logs)
            save_analysis_results(analysis_results, analysis_path)
            print(f"\n[Save] Saved {len(analysis_results)} error analyses from batch {batch_num}")
        
        # Print statistics after each batch
        stats.print_stats()
    
    print(f"\n{'='*60}")
    print(f"Processing complete!")
    print(f"{'='*60}\n")
    
    return stats.get_stats()


def main():
    """
    Main function to process all JSON files in the corpus root directory.
    """
    corpus_file = corpus_path / "humaneval-decompile.json"
    output_file = output_path / "batched_enriched_humaneval_decompile.json"
    
    stats = process_json_file(corpus_file, output_file)
    
    # Final statistics summary
    print("\n" + "="*60)
    print("FINAL STATISTICS SUMMARY")
    print("="*60)
    
    for opt_level, opt_stats in stats.items():
        total_opt = opt_stats["total"]
        c_fail_opt = opt_stats["compilation_failures"]
        e_fail_opt = opt_stats["execution_failures"]
        ce_success_opt = opt_stats["successful_executions"]
        
        if total_opt > 0:
            success_rate = (ce_success_opt / total_opt) * 100
            print(f"\nOptimization Level: {opt_level}")
            print(f"  Compilation failures: {c_fail_opt}/{total_opt} ({c_fail_opt/total_opt*100:.2f}%)")
            print(f"  Execution failures: {e_fail_opt}/{total_opt} ({e_fail_opt/total_opt*100:.2f}%)")
            print(f"  Successful executions: {ce_success_opt}/{total_opt} ({success_rate:.2f}%)")
    
    # Average success rate
    if stats:
        avg_rate = sum(
            (opt_stats["successful_executions"] / opt_stats["total"] * 100)
            for opt_stats in stats.values()
            if opt_stats["total"] > 0
        ) / len([s for s in stats.values() if s["total"] > 0])
        print(f"\nAverage Successful Execution Rate: {avg_rate:.2f}%")
    
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
