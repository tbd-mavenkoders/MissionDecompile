"""
ExeBench Re-Execution Evaluator - Highly Parallel Version

This evaluator tests the optimized code from exebench pipeline results against
the original IO pairs from the exebench corpus.

Features:
- True streaming parallelism with asyncio (50 concurrent workers)
- Combines individual JSON result files on-the-fly
- Tests against io_pairs from exebench corpus using the C++ test harness
- Stats similar to humaneval_re.py format
- Progress tracking and live stats
- Filters: only indices with both O0 and O3, skips llm_error cases

Usage:
  python -m evaluator.exebench_re --results-dir /path/to/v8 --max-workers 50
"""

import yaml
from pathlib import Path
import shutil
import tempfile
import os
import sys
import json
import subprocess
import asyncio
import time
import argparse
from typing import Tuple, List, Dict, Optional, Any, Set
from dataclasses import dataclass, field
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import threading
from queue import Queue
import re
import glob
from collections import defaultdict

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.compile import Compiler, OptimizationLevel

# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
print(f"Loading config from: {CONFIG_PATH}")

with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

corpus_path = Path(config["exebench"]["corpus_path"])
output_path = Path(config["exebench"]["output_path"])
clib_path = Path(config["exebench"]["clib_path"])

# Global compiler instance (thread-safe for read operations)
compiler = Compiler()


@dataclass
class TestResult:
    """Result from a single test case execution."""
    index: int
    opt: str
    unique_id: str
    compiled: bool
    executed: bool
    all_io_passed: bool
    io_tests_passed: int
    io_tests_total: int
    error_message: str = ""
    compile_time: float = 0.0
    exec_time: float = 0.0
    skipped: bool = False
    skip_reason: str = ""


@dataclass 
class Stats:
    """Accumulated statistics."""
    total: int = 0
    skipped: int = 0
    compilation_failures: int = 0
    execution_failures: int = 0
    io_failures: int = 0
    successful_executions: int = 0
    
    def __add__(self, other: 'Stats') -> 'Stats':
        return Stats(
            total=self.total + other.total,
            skipped=self.skipped + other.skipped,
            compilation_failures=self.compilation_failures + other.compilation_failures,
            execution_failures=self.execution_failures + other.execution_failures,
            io_failures=self.io_failures + other.io_failures,
            successful_executions=self.successful_executions + other.successful_executions,
        )


def load_exebench_corpus() -> Dict[str, Dict]:
    """Load the exebench corpus and index by (index, opt) for fast lookup."""
    corpus_file = corpus_path / "exebench_data.json"
    print(f"Loading exebench corpus from: {corpus_file}")
    
    with open(corpus_file, 'r') as f:
        corpus_list = json.load(f)
    
    # Index by "index_opt" format (e.g., "0_O0", "0_O3")
    corpus_dict = {}
    for item in corpus_list:
        idx = item['index']
        opt = item['opt']
        key = f"{idx}_{opt}"
        corpus_dict[key] = item
    
    print(f"Loaded {len(corpus_dict)} corpus entries")
    return corpus_dict


def compile_and_execute_io(
    c_code: str,
    func_head_types: str,
    io_input: Dict,
    io_output: Dict,
    temp_dir: Path,
    test_idx: int,
    timeout: int = 10
) -> Tuple[bool, bool, bool, str]:
    """
    Compile optimized code and test against a single IO pair.
    
    Returns: (compiled, executed, io_matched, message)
    """
    import json as json_module
    
    # Create source file with the optimized function and a test main
    func_name_match = re.search(r'(\w+)\s*\(', func_head_types)
    func_name = func_name_match.group(1) if func_name_match else "func"
    
    # Build a simple test harness
    # This is a simplified version - the real exebench uses nlohmann::json
    # For C functions, we generate a simple test
    source_file = temp_dir / f"test_{test_idx}.c"
    exe_file = temp_dir / f"test_{test_idx}"
    
    # Write source
    with open(source_file, 'w') as f:
        f.write(c_code)
    
    # Compile
    try:
        compile_cmd = [
            'gcc', str(source_file), '-o', str(exe_file),
            '-O0', '-w', '-lm'
        ]
        result = subprocess.run(
            compile_cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            return False, False, False, result.stderr[:500]
    except subprocess.TimeoutExpired:
        return False, False, False, "Compilation timeout"
    except Exception as e:
        return False, False, False, str(e)[:500]
    
    # Execute - for now, just check if it runs without crashing
    try:
        exec_result = subprocess.run(
            [str(exe_file)],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=temp_dir
        )
        if exec_result.returncode != 0:
            return True, False, False, exec_result.stderr[:500]
        
        # For basic pass, we just check it ran successfully
        # Full IO verification would need the nlohmann::json harness
        return True, True, True, ""
        
    except subprocess.TimeoutExpired:
        return True, False, False, "Execution timeout"
    except Exception as e:
        return True, False, False, str(e)[:500]


def build_test_harness(
    optimized_code: str,
    func_dep: str,
    func_head_types: str,
    test_harness: str,
    io_pair: Dict,
    temp_dir: Path
) -> Tuple[str, Path, Path]:
    """
    Build a complete test file using the exebench test harness pattern.
    
    Returns: (source_code, source_path, exe_path)
    """
    # Extract function name from signature
    func_name_match = re.search(r'(\w+)\s*\(', func_head_types)
    func_name = func_name_match.group(1) if func_name_match else "unknown_func"
    
    # Create a temporary C file for the optimized function
    func_file = temp_dir / "optimized_func.c"
    with open(func_file, 'w') as f:
        # Write dependencies and optimized code
        f.write(func_dep + "\n\n")
        # Add dummy_funcs if present
        if io_pair.get('dummy_funcs'):
            f.write(io_pair['dummy_funcs'] + "\n\n")
        f.write(optimized_code + "\n")
    
    # Modify test harness to include our function file
    # The original test harness includes from a temp file path
    modified_test = test_harness
    
    # Replace the extern C include with our file
    modified_test = re.sub(
        r'extern\s+"C"\s*\{[^}]*\}',
        f'extern "C" {{\n#include "{func_file}"\n}}',
        modified_test
    )
    
    # Also try the #include pattern
    modified_test = re.sub(
        r'#include\s+"/tmp/[^"]*\.c"',
        f'#include "{func_file}"',
        modified_test
    )
    
    source_file = temp_dir / "test_main.cpp"
    exe_file = temp_dir / "test_exe"
    
    with open(source_file, 'w') as f:
        f.write(modified_test)
    
    return modified_test, source_file, exe_file


def run_exebench_io_test(
    optimized_code: str,
    corpus_entry: Dict,
    temp_base: Path
) -> TestResult:
    """
    Test optimized code against all IO pairs from corpus entry.
    
    This uses the exebench test harness approach with nlohmann::json.
    """
    index = corpus_entry['index']
    opt = corpus_entry['opt']
    unique_id = f"{index}_{opt}"
    io_pairs = corpus_entry.get('io_pairs', [])
    func_dep = corpus_entry.get('func_dep', '')
    func_head_types = corpus_entry.get('func_head_types', '')
    test_harness = corpus_entry.get('test', '')
    
    if not io_pairs:
        return TestResult(
            index=index,
            opt=opt,
            unique_id=unique_id,
            compiled=False,
            executed=False,
            all_io_passed=False,
            io_tests_passed=0,
            io_tests_total=0,
            error_message="No IO pairs available"
        )
    
    # Create temp directory for this test
    temp_dir = temp_base / f"test_{unique_id}"
    temp_dir.mkdir(parents=True, exist_ok=True)
    
    io_passed = 0
    io_total = len(io_pairs)
    last_error = ""
    compiled = False
    executed = False
    
    start_time = time.time()
    
    try:
        for io_idx, io_pair in enumerate(io_pairs):
            # Build the test harness with current IO pair
            try:
                _, source_file, exe_file = build_test_harness(
                    optimized_code=optimized_code,
                    func_dep=func_dep,
                    func_head_types=func_head_types,
                    test_harness=test_harness,
                    io_pair=io_pair,
                    temp_dir=temp_dir
                )
                
                # Compile with g++ (exebench uses C++ test harness)
                compile_cmd = [
                    'g++', str(source_file), '-o', str(exe_file),
                    '-O0', '-w', '-lm',
                    '-I/usr/include',  # nlohmann/json
                ]
                
                compile_result = subprocess.run(
                    compile_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if compile_result.returncode != 0:
                    last_error = f"Compile error: {compile_result.stderr[:300]}"
                    continue
                
                compiled = True
                
                # Create input JSON file
                input_json_file = temp_dir / f"input_{io_idx}.json"
                output_json_file = temp_dir / f"output_{io_idx}.json"
                
                with open(input_json_file, 'w') as f:
                    json.dump(io_pair['input'], f)
                
                # Execute
                exec_result = subprocess.run(
                    [str(exe_file), str(input_json_file), str(output_json_file)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=temp_dir
                )
                
                if exec_result.returncode != 0:
                    last_error = f"Exec error: {exec_result.stderr[:300]}"
                    continue
                
                executed = True
                
                # Compare output
                if output_json_file.exists():
                    with open(output_json_file, 'r') as f:
                        actual_output = json.load(f)
                    
                    expected_output = io_pair['output']
                    
                    # Simple comparison (could be more sophisticated)
                    if actual_output == expected_output:
                        io_passed += 1
                    else:
                        last_error = f"IO mismatch: expected {expected_output}, got {actual_output}"
                else:
                    last_error = "No output file generated"
                    
            except subprocess.TimeoutExpired:
                last_error = "Timeout"
            except Exception as e:
                last_error = str(e)[:200]
    
    finally:
        # Cleanup
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except:
            pass
    
    elapsed = time.time() - start_time
    
    return TestResult(
        index=index,
        opt=opt,
        unique_id=unique_id,
        compiled=compiled,
        executed=executed,
        all_io_passed=(io_passed == io_total and io_total > 0),
        io_tests_passed=io_passed,
        io_tests_total=io_total,
        error_message=last_error,
        exec_time=elapsed
    )


def simple_compile_test(
    optimized_code: str,
    corpus_entry: Dict,
    temp_base: Path
) -> TestResult:
    """
    Full IO test: compile and execute against all IO pairs from corpus.
    
    Uses the exebench test harness with nlohmann::json for proper IO testing.
    """
    index = corpus_entry['index']
    opt = corpus_entry['opt']
    unique_id = f"{index}_{opt}"
    func_dep = corpus_entry.get('func_dep', '')
    func_head_types = corpus_entry.get('func_head_types', '')
    test_harness = corpus_entry.get('test', '')
    io_pairs = corpus_entry.get('io_pairs', [])
    
    # Create temp directory
    temp_dir = temp_base / f"test_{unique_id}"
    temp_dir.mkdir(parents=True, exist_ok=True)
    
    start_time = time.time()
    compiled = False
    executed = False
    io_passed = 0
    io_total = len(io_pairs)
    last_error = ""
    
    try:
        # Write the optimized function to a C file
        func_file = temp_dir / "optimized_func.c"
        with open(func_file, 'w') as f:
            f.write(func_dep + "\n\n")
            f.write(optimized_code + "\n")
        
        # Modify test harness to include our function
        # The test harness expects to include a .c file via extern "C"
        modified_test = test_harness
        
        # Replace temp file paths with our function file
        modified_test = re.sub(
            r'#include\s+"/tmp/[^"]*\.c"',
            f'#include "{func_file}"',
            modified_test
        )
        
        # Also handle extern "C" block style
        modified_test = re.sub(
            r'extern\s+"C"\s*\{\s*#include\s+"/tmp/[^"]*\.c"\s*\}',
            f'extern "C" {{\n#include "{func_file}"\n}}',
            modified_test
        )
        
        source_file = temp_dir / "test_main.cpp"
        exe_file = temp_dir / "test_exe"
        
        with open(source_file, 'w') as f:
            f.write(modified_test)
        
        # Compile with g++ (exebench uses C++ test harness with nlohmann::json)
        compile_cmd = [
            'g++', str(source_file), '-o', str(exe_file),
            '-O0', '-w', '-lm',
            f'-I{clib_path}',
            '-I/usr/include',
            '-std=c++17'
        ]
        
        compile_result = subprocess.run(
            compile_cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if compile_result.returncode != 0:
            last_error = f"Compile error: {compile_result.stderr[:500]}"
            return TestResult(
                index=index,
                opt=opt,
                unique_id=unique_id,
                compiled=False,
                executed=False,
                all_io_passed=False,
                io_tests_passed=0,
                io_tests_total=io_total,
                error_message=last_error,
                compile_time=time.time() - start_time
            )
        
        compiled = True
        
        # Test each IO pair
        for io_idx, io_pair in enumerate(io_pairs):
            try:
                # Handle dummy_funcs if present
                if io_pair.get('dummy_funcs'):
                    # Need to recompile with dummy_funcs
                    with open(func_file, 'w') as f:
                        f.write(func_dep + "\n\n")
                        f.write(io_pair['dummy_funcs'] + "\n\n")
                        f.write(optimized_code + "\n")
                    
                    # Recompile
                    compile_result = subprocess.run(
                        compile_cmd,
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    if compile_result.returncode != 0:
                        last_error = f"Recompile with dummy_funcs failed: {compile_result.stderr[:300]}"
                        continue
                
                # Write input JSON
                input_json_file = temp_dir / f"input_{io_idx}.json"
                output_json_file = temp_dir / f"output_{io_idx}.json"
                
                with open(input_json_file, 'w') as f:
                    json.dump(io_pair['input'], f)
                
                # Execute test
                exec_result = subprocess.run(
                    [str(exe_file), str(input_json_file), str(output_json_file)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    cwd=temp_dir
                )
                
                if exec_result.returncode != 0:
                    last_error = f"Exec error (IO {io_idx}): {exec_result.stderr[:200]}"
                    continue
                
                executed = True
                
                # Compare output
                if output_json_file.exists():
                    with open(output_json_file, 'r') as f:
                        actual_output = json.load(f)
                    
                    expected_output = io_pair['output']
                    
                    # Compare outputs (handle floating point tolerance if needed)
                    if compare_outputs(actual_output, expected_output):
                        io_passed += 1
                    else:
                        last_error = f"IO mismatch (IO {io_idx}): expected {str(expected_output)[:100]}, got {str(actual_output)[:100]}"
                else:
                    last_error = f"No output file for IO {io_idx}"
                    
            except subprocess.TimeoutExpired:
                last_error = f"Timeout on IO {io_idx}"
            except Exception as e:
                last_error = f"Exception on IO {io_idx}: {str(e)[:100]}"
    
    except subprocess.TimeoutExpired:
        last_error = "Compilation timeout"
    except Exception as e:
        last_error = str(e)[:200]
    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except:
            pass
    
    elapsed = time.time() - start_time
    
    return TestResult(
        index=index,
        opt=opt,
        unique_id=unique_id,
        compiled=compiled,
        executed=executed,
        all_io_passed=(io_passed == io_total and io_total > 0),
        io_tests_passed=io_passed,
        io_tests_total=io_total,
        error_message=last_error,
        exec_time=elapsed
    )


def compare_outputs(actual: Any, expected: Any, tolerance: float = 1e-6) -> bool:
    """Compare outputs with tolerance for floating point values."""
    if type(actual) != type(expected):
        # Try numeric comparison
        if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
            return abs(float(actual) - float(expected)) < tolerance
        return False
    
    if isinstance(actual, dict):
        if set(actual.keys()) != set(expected.keys()):
            return False
        return all(compare_outputs(actual[k], expected[k], tolerance) for k in actual)
    
    if isinstance(actual, list):
        if len(actual) != len(expected):
            return False
        return all(compare_outputs(a, e, tolerance) for a, e in zip(actual, expected))
    
    if isinstance(actual, float):
        return abs(actual - expected) < tolerance
    
    return actual == expected


def process_single_result(
    result_file: Path,
    corpus: Dict[str, Dict],
    temp_base: Path,
    valid_indices: Set[int] = None
) -> Optional[TestResult]:
    """Process a single result JSON file and test it.
    
    Args:
        result_file: Path to the result JSON file
        corpus: The exebench corpus indexed by "index_opt"
        temp_base: Base temp directory for test files
        valid_indices: Set of indices that have both O0 and O3 results (if None, accept all)
    """
    
    try:
        with open(result_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading {result_file}: {e}")
        return None
    
    index = data.get('index')
    opt = data.get('opt')
    unique_id = data.get('unique_id', f"{index}_{opt}")
    
    # Filter: only include indices with both O0 and O3
    if valid_indices is not None and index not in valid_indices:
        return TestResult(
            index=index,
            opt=opt,
            unique_id=unique_id,
            compiled=False,
            executed=False,
            all_io_passed=False,
            io_tests_passed=0,
            io_tests_total=0,
            error_message="",
            skipped=True,
            skip_reason="Missing O0 or O3 counterpart"
        )
    
    # Get corpus entry
    corpus_key = f"{index}_{opt}"
    corpus_entry = corpus.get(corpus_key)
    
    if not corpus_entry:
        return TestResult(
            index=index,
            opt=opt,
            unique_id=unique_id,
            compiled=False,
            executed=False,
            all_io_passed=False,
            io_tests_passed=0,
            io_tests_total=0,
            error_message="",
            skipped=True,
            skip_reason=f"No corpus entry for {corpus_key}"
        )
    
    # Find optimized code from functions, check for llm_error
    optimized_code = ""
    functions = data.get('functions', [])
    
    for func in functions:
        # Check for llm_error - skip if present
        if func.get('llm_error'):
            return TestResult(
                index=index,
                opt=opt,
                unique_id=unique_id,
                compiled=False,
                executed=False,
                all_io_passed=False,
                io_tests_passed=0,
                io_tests_total=len(corpus_entry.get('io_pairs', [])),
                error_message="",
                skipped=True,
                skip_reason=f"LLM error: {str(func.get('llm_error'))[:100]}"
            )
        
        if func.get('optimization_status') == True:
            optimized_code = func.get('optimized_code', '')
            break
    
    if not optimized_code:
        # No successful optimization (but not an llm_error)
        return TestResult(
            index=index,
            opt=opt,
            unique_id=unique_id,
            compiled=False,
            executed=False,
            all_io_passed=False,
            io_tests_passed=0,
            io_tests_total=len(corpus_entry.get('io_pairs', [])),
            error_message="No optimized code available"
        )
    
    # Run the full IO test
    return simple_compile_test(optimized_code, corpus_entry, temp_base)


async def process_file_async(
    result_file: Path,
    corpus: Dict[str, Dict],
    temp_base: Path,
    executor: ProcessPoolExecutor,
    valid_indices: Set[int] = None
) -> Optional[TestResult]:
    """Process a single file asynchronously using process pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        executor,
        process_single_result,
        result_file,
        corpus,
        temp_base,
        valid_indices
    )


def find_valid_indices(results_dir: Path) -> Set[int]:
    """Find indices that have both O0 and O3 results."""
    json_files = list(results_dir.glob("func_*.json"))
    indices_by_opt = defaultdict(set)
    
    for f in json_files:
        # Parse filename to get index and opt
        # Format: func_{index}_{opt}.json
        match = re.match(r'func_(\d+)_(O\d+)\.json', f.name)
        if match:
            idx = int(match.group(1))
            opt = match.group(2)
            indices_by_opt[idx].add(opt)
    
    # Return indices that have both O0 and O3
    valid = {idx for idx, opts in indices_by_opt.items() if 'O0' in opts and 'O3' in opts}
    return valid


async def run_parallel_evaluation(
    results_dir: Path,
    corpus: Dict[str, Dict],
    max_workers: int = 50
) -> Tuple[Dict[str, Stats], List[TestResult]]:
    """
    Run parallel evaluation with streaming parallelism.
    
    Maintains max_workers concurrent tasks at all times.
    Filters to only indices with both O0 and O3, skips llm_error cases.
    """
    # Find all JSON result files
    json_files = list(results_dir.glob("func_*.json"))
    total_files = len(json_files)
    
    print(f"Found {total_files} result files to process")
    
    # Find valid indices (those with both O0 and O3)
    valid_indices = find_valid_indices(results_dir)
    print(f"Found {len(valid_indices)} indices with both O0 and O3 results")
    print(f"Using {max_workers} parallel workers")
    
    # Create temp directory for all tests
    temp_base = Path(tempfile.mkdtemp(prefix="exebench_re_"))
    print(f"Temp directory: {temp_base}")
    
    # Stats by optimization level
    stats_by_opt: Dict[str, Stats] = {}
    all_results: List[TestResult] = []
    
    # Progress tracking
    completed = 0
    skipped_count = 0
    start_time = time.time()
    
    # Semaphore to limit concurrency
    semaphore = asyncio.Semaphore(max_workers)
    
    async def process_with_semaphore(
        result_file: Path,
        executor: ProcessPoolExecutor
    ) -> Optional[TestResult]:
        async with semaphore:
            return await process_file_async(result_file, corpus, temp_base, executor, valid_indices)
    
    # Use ProcessPoolExecutor for CPU-bound work
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        tasks = [
            process_with_semaphore(f, executor)
            for f in json_files
        ]
        
        # Process with progress updates
        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            
            if result:
                all_results.append(result)
                
                # Handle skipped cases
                if result.skipped:
                    skipped_count += 1
                    # Still track in stats
                    opt = result.opt
                    if opt not in stats_by_opt:
                        stats_by_opt[opt] = Stats()
                    stats_by_opt[opt].total += 1
                    stats_by_opt[opt].skipped += 1
                    continue
                
                # Update stats for non-skipped
                opt = result.opt
                if opt not in stats_by_opt:
                    stats_by_opt[opt] = Stats()
                
                stats = stats_by_opt[opt]
                stats.total += 1
                
                if not result.compiled:
                    stats.compilation_failures += 1
                elif not result.executed:
                    stats.execution_failures += 1
                elif not result.all_io_passed:
                    stats.io_failures += 1
                else:
                    stats.successful_executions += 1
            
            # Progress update every 50 files
            if completed % 50 == 0 or completed == total_files:
                elapsed = time.time() - start_time
                rate = completed / elapsed if elapsed > 0 else 0
                eta = (total_files - completed) / rate if rate > 0 else 0
                
                print(f"\rProgress: {completed}/{total_files} ({100*completed/total_files:.1f}%) "
                      f"| Skipped: {skipped_count} | Rate: {rate:.1f} files/s | ETA: {eta:.0f}s", end="", flush=True)
    
    print()  # Newline after progress
    
    # Cleanup
    try:
        shutil.rmtree(temp_base, ignore_errors=True)
    except:
        pass
    
    return stats_by_opt, all_results


def print_stats(stats_by_opt: Dict[str, Stats]):
    """Print statistics in humaneval_re.py format."""
    
    print("\n" + "="*80)
    print("EXEBENCH RE-EXECUTION RESULTS")
    print("="*80)
    
    # Print stats for each optimization level
    for opt_level in sorted(stats_by_opt.keys()):
        stats = stats_by_opt[opt_level]
        tested = stats.total - stats.skipped
        if tested > 0:
            success_rate = stats.successful_executions / tested * 100
            print(f"\nOptimization Level: {opt_level}")
            print(f"  Total files: {stats.total}")
            print(f"  Skipped (no pair/llm_error): {stats.skipped}")
            print(f"  Actually tested: {tested}")
            print(f"  Compilation failures: {stats.compilation_failures}")
            print(f"  Execution failures: {stats.execution_failures}")
            print(f"  IO failures: {stats.io_failures}")
            print(f"  Successful (all IO passed): {stats.successful_executions}")
            print(f"  Success Rate: {success_rate:.2f}%")
        elif stats.total > 0:
            print(f"\nOptimization Level: {opt_level}")
            print(f"  Total files: {stats.total}")
            print(f"  All skipped: {stats.skipped}")
    
    # Overall stats
    total_stats = Stats()
    for stats in stats_by_opt.values():
        total_stats = total_stats + stats
    
    tested = total_stats.total - total_stats.skipped
    if tested > 0:
        overall_rate = total_stats.successful_executions / tested * 100
        print(f"\n{'='*80}")
        print("OVERALL STATISTICS")
        print(f"{'='*80}")
        print(f"Total files processed: {total_stats.total}")
        print(f"Skipped (missing pair or llm_error): {total_stats.skipped}")
        print(f"Actually tested: {tested}")
        print(f"Compilation failures: {total_stats.compilation_failures}")
        print(f"Execution failures: {total_stats.execution_failures}")
        print(f"IO failures: {total_stats.io_failures}")
        print(f"Successful (all IO passed): {total_stats.successful_executions}")
        print(f"Overall Success Rate: {overall_rate:.2f}%")
    
    # Per-opt average (excluding skipped)
    if stats_by_opt:
        rates = []
        for s in stats_by_opt.values():
            tested = s.total - s.skipped
            if tested > 0:
                rates.append(s.successful_executions / tested * 100)
        if rates:
            avg_rate = sum(rates) / len(rates)
            print(f"\nAverage Success Rate across optimization levels: {avg_rate:.2f}%")


def save_results(
    stats_by_opt: Dict[str, Stats],
    all_results: List[TestResult],
    output_file: Path
):
    """Save detailed results to JSON."""
    
    output_data = {
        "stats_by_opt": {
            opt: {
                "total": s.total,
                "skipped": s.skipped,
                "tested": s.total - s.skipped,
                "compilation_failures": s.compilation_failures,
                "execution_failures": s.execution_failures,
                "io_failures": s.io_failures,
                "successful_executions": s.successful_executions,
                "success_rate": s.successful_executions / (s.total - s.skipped) * 100 if (s.total - s.skipped) > 0 else 0
            }
            for opt, s in stats_by_opt.items()
        },
        "detailed_results": [
            {
                "index": r.index,
                "opt": r.opt,
                "unique_id": r.unique_id,
                "skipped": r.skipped,
                "skip_reason": r.skip_reason,
                "compiled": r.compiled,
                "executed": r.executed,
                "all_io_passed": r.all_io_passed,
                "io_tests_passed": r.io_tests_passed,
                "io_tests_total": r.io_tests_total,
                "error_message": r.error_message,
                "exec_time": r.exec_time
            }
            for r in all_results
        ]
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\nDetailed results saved to: {output_file}")


def combine_result_jsons(results_dir: Path, output_file: Path):
    """Combine all individual JSON files into a single combined_results.json."""
    
    json_files = sorted(results_dir.glob("func_*.json"))
    print(f"Combining {len(json_files)} JSON files...")
    
    combined = []
    for jf in json_files:
        try:
            with open(jf, 'r') as f:
                data = json.load(f)
                combined.append(data)
        except Exception as e:
            print(f"Error loading {jf}: {e}")
    
    with open(output_file, 'w') as f:
        json.dump(combined, f, indent=2)
    
    print(f"Combined {len(combined)} results into: {output_file}")
    return combined


async def main_async(args):
    """Main async entry point."""
    
    results_dir = Path(args.results_dir)
    
    if not results_dir.exists():
        print(f"Error: Results directory not found: {results_dir}")
        sys.exit(1)
    
    # Load corpus
    corpus = load_exebench_corpus()
    
    # Optionally combine JSONs first
    if args.combine_first:
        combined_file = results_dir / "combined_results.json"
        combine_result_jsons(results_dir, combined_file)
    
    # Run parallel evaluation
    print(f"\nStarting parallel evaluation with {args.max_workers} workers...")
    start_time = time.time()
    
    stats_by_opt, all_results = await run_parallel_evaluation(
        results_dir=results_dir,
        corpus=corpus,
        max_workers=args.max_workers
    )
    
    elapsed = time.time() - start_time
    print(f"\nTotal evaluation time: {elapsed:.1f}s")
    
    # Print statistics
    print_stats(stats_by_opt)
    
    # Save detailed results
    if args.output:
        save_results(stats_by_opt, all_results, Path(args.output))
    else:
        default_output = results_dir / "re_evaluation_results.json"
        save_results(stats_by_opt, all_results, default_output)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="ExeBench Re-Execution Evaluator - Highly Parallel Version"
    )
    parser.add_argument(
        "--results-dir",
        type=str,
        default=str(output_path / "run_20260206_011917/v8"),
        help="Directory containing result JSON files"
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=50,
        help="Maximum number of parallel workers (default: 50)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file for detailed results"
    )
    parser.add_argument(
        "--combine-first",
        action="store_true",
        help="Combine individual JSONs into combined_results.json first"
    )
    
    args = parser.parse_args()
    
    # Run async main
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
