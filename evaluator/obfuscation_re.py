"""
Re-evaluation script for obfuscation decompilation results.
Compiles the optimized code with test cases and checks execution.
"""

import yaml
from pathlib import Path
from ..utils.compile import Compiler, OptimizationLevel
import tempfile
import json
import subprocess
from typing import Tuple, Dict


c = Compiler()


# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
print(f"Loading config from: {CONFIG_PATH}")

with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

output_path = Path(config.get("obfuscation", {}).get("output_path", 
                   "/workspace/home/b220032cs/fyp/repos/ansaf/Experiments/v8-GemTypesandVEX/VERITAS/output/obfuscation"))


def compile_and_execute(c_file_path: Path, language: str = "c") -> Tuple[bool, bool, str]:
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
        res = subprocess.run(command, cwd=output_executable.parent, capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            return True, True, res.stdout
        else:
            return True, False, res.stderr
    except Exception as e:
        return True, False, str(e)


def process_results_file(output_file: Path) -> Dict:
    """
    Process the combined_results.json file from obfuscation output.
    """
    # Stats by obfuscation type
    bogus_stats = {"total": 0, "compilation_failures": 0, "execution_failures": 0, "successful_executions": 0}
    cff_stats = {"total": 0, "compilation_failures": 0, "execution_failures": 0, "successful_executions": 0}
    
    # Combined stats
    overall_stats = {"total": 0, "compilation_failures": 0, "execution_failures": 0, "successful_executions": 0}
    
    # Load the output JSON file
    with open(output_file, "r") as f:
        output = json.load(f)
    
    print(f"Loaded {len(output)} results from {output_file}")
    print("=" * 80)
    
    for data in output:
        corpus_index = data["index"]
        obfuscation_type = data.get("obfuscation_type", "unknown")
        opt = data.get("opt", "O2")
        
        # Get the optimized code
        optimized_code = ""
        for function in data.get("functions", []):
            if function.get("f_name") == "func0" and function.get("optimization_status") == True:
                optimized_code = function.get("optimized_code", "")
                break
        
        if not optimized_code:
            continue
            
        test_code = data.get("test", "")
        func_dep = data.get("func_dep", "")
        
        # Select appropriate stats dict
        if obfuscation_type == "bogus":
            stats = bogus_stats
        elif obfuscation_type == "cff":
            stats = cff_stats
        else:
            continue
            
        stats["total"] += 1
        overall_stats["total"] += 1
        
        # Build the complete C code
        c_include = func_dep + "\n"
        c_optimized = optimized_code
        c_test = test_code
        
        # Extract includes from optimized code
        for line in optimized_code.splitlines():
            if "include" in line:
                c_include += line + "\n"
                c_optimized = c_optimized.replace(line, "")
        
        # Extract includes from test code
        for line in test_code.splitlines():
            if "include" in line:
                c_include += line + "\n"
                c_test = c_test.replace(line, "")
        
        original_c_code = c_include + "\n" + c_optimized + "\n" + c_test
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = Path(temp_dir)
            c_file_path = temp_dir_path / "temp_code.c"
            with open(c_file_path, "w") as f:
                f.write(original_c_code)
            
            # Attempt to compile and execute
            compiled, executed, runtime_message = compile_and_execute(c_file_path, "c")
            
            if not compiled:
                stats["compilation_failures"] += 1
                overall_stats["compilation_failures"] += 1
                print(f"[{obfuscation_type.upper()}] P{corpus_index} - Compilation Error: {runtime_message[:100]}...")
            elif compiled and executed:
                stats["successful_executions"] += 1
                overall_stats["successful_executions"] += 1
            else:
                stats["execution_failures"] += 1
                overall_stats["execution_failures"] += 1
                print(f"[{obfuscation_type.upper()}] P{corpus_index} - Execution Error: {runtime_message[:100]}...")
    
    # Print final statistics
    print("\n" + "=" * 80)
    print("FINAL STATISTICS")
    print("=" * 80)
    
    # Bogus stats
    if bogus_stats["total"] > 0:
        success_rate = bogus_stats["successful_executions"] / bogus_stats["total"] * 100
        print(f"\n[BOGUS] Total: {bogus_stats['total']}")
        print(f"  - Compilation Failures: {bogus_stats['compilation_failures']}")
        print(f"  - Execution Failures: {bogus_stats['execution_failures']}")
        print(f"  - Successful Executions: {bogus_stats['successful_executions']}")
        print(f"  - Success Rate: {success_rate:.2f}%")
    
    # CFF stats
    if cff_stats["total"] > 0:
        success_rate = cff_stats["successful_executions"] / cff_stats["total"] * 100
        print(f"\n[CFF] Total: {cff_stats['total']}")
        print(f"  - Compilation Failures: {cff_stats['compilation_failures']}")
        print(f"  - Execution Failures: {cff_stats['execution_failures']}")
        print(f"  - Successful Executions: {cff_stats['successful_executions']}")
        print(f"  - Success Rate: {success_rate:.2f}%")
    
    # Overall stats
    if overall_stats["total"] > 0:
        success_rate = overall_stats["successful_executions"] / overall_stats["total"] * 100
        print(f"\n[OVERALL] Total: {overall_stats['total']}")
        print(f"  - Compilation Failures: {overall_stats['compilation_failures']}")
        print(f"  - Execution Failures: {overall_stats['execution_failures']}")
        print(f"  - Successful Executions: {overall_stats['successful_executions']}")
        print(f"  - Success Rate: {success_rate:.2f}%")
    
    print("=" * 80)
    
    return {
        "bogus": bogus_stats,
        "cff": cff_stats,
        "overall": overall_stats
    }


def main():
    """
    Main function to process the obfuscation results.
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="Re-evaluate obfuscation decompilation results")
    parser.add_argument("--run-dir", type=str, 
                        default="/workspace/home/b220032cs/fyp/repos/ansaf/Experiments/v8-GemTypesandVEX/VERITAS/output/obfuscation/run_20260206_080108",
                        help="Path to the run directory")
    parser.add_argument("--version", type=str, default="v8", choices=["v4_5", "v8"],
                        help="Which version results to evaluate (v4_5 or v8)")
    
    args = parser.parse_args()
    
    run_dir = Path(args.run_dir)
    output_file = run_dir / args.version / "combined_results.json"
    
    if not output_file.exists():
        print(f"Error: Output file not found: {output_file}")
        return
    
    print(f"Evaluating {args.version} results from: {output_file}")
    print("=" * 80)
    
    stats = process_results_file(output_file)


if __name__ == "__main__":
    main()
