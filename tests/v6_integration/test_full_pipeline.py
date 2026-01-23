#!/usr/bin/env python3
"""
Full Pipeline Test for MissionDecompile V6 with VexHelix

This test runs the complete pipeline:
1. Load 10 C + 10 C++ samples from HumanEval
2. Compile original code to binary
3. Use LLM to repair Ghidra pseudo code
4. Send to VexHelix for verification
5. Iterate until VexHelix returns "equivalent"

GOAL: All samples should reach "equivalent" status without VexHelix errors.
"""

import sys
import json
import time
import tempfile
import subprocess
import requests
import yaml
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# Add parent directories to path
SCRIPT_DIR = Path(__file__).resolve().parent
MISSION_DIR = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(MISSION_DIR))

from utils.llm_interface import create_llm_interface, LLMInterface
from utils.compile import Compiler, OptimizationLevel

# =============================================================================
# CONFIGURATION
# =============================================================================

# Load config
CONFIG_PATH = MISSION_DIR / "config.yaml"
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

# Paths
DATASET_PATH = Path(config["humaneval"]["corpus_path"]) / "humaneval-decompile.json"
OUTPUT_DIR = SCRIPT_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

# API Configuration
VEXHELIX_API_URL = "http://127.0.0.1:8001"
VEXHELIX_TIMEOUT = 120

# Test Configuration
NUM_C_SAMPLES = 10
NUM_CPP_SAMPLES = 10
MAX_REPAIR_ITERATIONS = 10
MAX_STATIC_REPAIR_PER_CYCLE = 3
CONCURRENT_WORKERS = 8

# Initialize compiler
compiler = Compiler()


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class SampleResult:
    """Result of processing a single sample."""
    index: int
    language: str
    success: bool
    final_status: str  # "equivalent", "different", "error", "timeout", "compile_failed"
    iterations: int
    vexhelix_calls: int
    static_repairs: int
    duration: float
    error_message: Optional[str] = None
    final_code: Optional[str] = None


@dataclass
class BatchResult:
    """Result of processing a batch of samples."""
    total: int
    equivalent: int
    different: int
    errors: int
    timeouts: int
    compile_failures: int
    total_time: float
    results: List[SampleResult] = field(default_factory=list)


# =============================================================================
# LLM INTERFACE
# =============================================================================

# Create LLM interface
llm_interface = create_llm_interface(
    provider=config["llm"]["vllm_provider"],
    model_name=config["llm"]["vllm_model_name"],
    base_url=config["llm"]["vllm_base_url"]
)


# =============================================================================
# VEXHELIX API CLIENT
# =============================================================================

def check_vexhelix_health() -> bool:
    """Check if VexHelix API is available."""
    try:
        response = requests.get(f"{VEXHELIX_API_URL}/health", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"VexHelix API: {data.get('status')} (v{data.get('version')})")
            return data.get('status') == 'healthy'
    except Exception as e:
        print(f"VexHelix API unavailable: {e}")
    return False


def call_vexhelix(
    binary_path: Path,
    decompiled_code: str,
    function_name: str,
    language: str,
    num_args: int = 3
) -> Dict:
    """
    Call VexHelix API for verification.
    
    Returns:
        Dict with keys: status, equivalent, message, compilation_error, divergences
    """
    try:
        with open(binary_path, 'rb') as f:
            response = requests.post(
                f"{VEXHELIX_API_URL}/verify",
                data={
                    'decompiled_code': decompiled_code,
                    'function_name': function_name,
                    'language': language,
                    'num_args': str(num_args),
                    'loop_bound': '5',
                    'timeout': str(VEXHELIX_TIMEOUT)
                },
                files={'original_binary': (binary_path.name, f, 'application/octet-stream')},
                timeout=VEXHELIX_TIMEOUT + 30
            )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {
                'status': 'error',
                'message': f"HTTP {response.status_code}: {response.text[:200]}"
            }
    except requests.exceptions.Timeout:
        return {'status': 'timeout', 'message': 'Request timed out'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}


# =============================================================================
# PROMPT GENERATION
# =============================================================================

def get_initial_prompt(ghidra_code: str, language: str) -> str:
    """Generate initial LLM prompt."""
    system_prompt = config["prompts"]["system_prompt"]
    return f"{system_prompt}\n\n```{language}\n{ghidra_code}\n```"


def get_static_repair_prompt(code: str, errors: str, language: str) -> str:
    """Generate static repair prompt for compilation errors."""
    repair_prompt = config["prompts"]["compilation_error"]
    return f"{repair_prompt}\n\n```{language}\n{code}\n```\n\nCompilation Errors:\n{errors}"


def get_semantic_repair_prompt(
    original_ghidra: str,
    current_code: str,
    vexhelix_result: Dict,
    language: str
) -> str:
    """Generate semantic repair prompt for logical errors."""
    semantic_prompt = config["prompts"]["semantic_repair"]
    
    prompt = f"{semantic_prompt}\n\n"
    prompt += f"Language: {language.upper()}\n\n"
    prompt += f"Original Ghidra Decompilation:\n```{language}\n{original_ghidra}\n```\n\n"
    prompt += f"Current Code (INCORRECT):\n```{language}\n{current_code}\n```\n\n"
    prompt += f"VexHelix Result: DIFFERENT (semantic mismatch detected)\n\n"
    
    # Add divergence info if available
    divergences = vexhelix_result.get('divergences', [])
    if divergences:
        prompt += "Divergence Details:\n"
        for i, div in enumerate(divergences[:3]):
            prompt += f"  Divergence {i+1}: {div}\n"
        prompt += "\n"
    
    prompt += "Please fix the logical errors to match the original behavior."
    return prompt


# =============================================================================
# COMPILATION
# =============================================================================

def compile_original(code: str, language: str, output_dir: Path) -> Optional[Path]:
    """Compile original code to binary."""
    ext = ".cpp" if language == "cpp" else ".c"
    src_path = output_dir / f"original{ext}"
    bin_path = output_dir / "original.bin"
    
    # Write source
    src_path.write_text(code)
    
    # Compile
    status, message = compiler.compile_source(
        source_file_path=src_path,
        output_file_path=bin_path,
        opt=OptimizationLevel.O0,
        is_cpp=(language == "cpp"),
        c_flag=True
    )
    
    if status and bin_path.exists():
        return bin_path
    else:
        print(f"  Original compile failed: {message[:100]}")
        return None


def compile_decompiled(code: str, language: str, output_dir: Path) -> Tuple[bool, str]:
    """Try to compile decompiled code. Returns (success, error_message)."""
    ext = ".cpp" if language == "cpp" else ".c"
    src_path = output_dir / f"decompiled{ext}"
    bin_path = output_dir / "decompiled.bin"
    
    # Write source
    src_path.write_text(code)
    
    # Compile
    cc = "g++" if language == "cpp" else "gcc"
    result = subprocess.run(
        [cc, "-O0", "-fno-stack-protector", "-w", str(src_path), "-o", str(bin_path), "-lm"],
        capture_output=True,
        text=True,
        timeout=30
    )
    
    if result.returncode == 0 and bin_path.exists():
        return True, ""
    else:
        return False, result.stderr


# =============================================================================
# MAIN PIPELINE
# =============================================================================

def process_sample(sample: Dict, output_base: Path) -> SampleResult:
    """
    Process a single sample through the full pipeline.
    
    Pipeline:
    1. Compile original code
    2. Generate initial LLM repair
    3. Static repair loop until compilable
    4. VexHelix verification
    5. Semantic repair loop until equivalent
    """
    start_time = time.time()
    idx = sample['index']
    language = sample['language']
    
    output_dir = output_base / f"sample_{idx}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    stats = {
        'iterations': 0,
        'vexhelix_calls': 0,
        'static_repairs': 0
    }
    
    print(f"\n[Sample {idx}] Processing ({language.upper()})...")
    
    try:
        # Step 1: Compile original code
        original_code = sample['func_dep'] + sample['func']
        original_binary = compile_original(original_code, language, output_dir)
        
        if not original_binary:
            return SampleResult(
                index=idx,
                language=language,
                success=False,
                final_status="compile_failed",
                iterations=0,
                vexhelix_calls=0,
                static_repairs=0,
                duration=time.time() - start_time,
                error_message="Original code failed to compile"
            )
        
        print(f"  [1/4] Original compiled successfully")
        
        # Step 2: Generate initial LLM repair
        ghidra_code = sample['ghidra_pseudo']
        initial_prompt = get_initial_prompt(ghidra_code, language)
        current_code = llm_interface.generate(initial_prompt)
        
        print(f"  [2/4] LLM generated initial code")
        
        # Main iteration loop
        for iteration in range(MAX_REPAIR_ITERATIONS):
            stats['iterations'] = iteration + 1
            
            # Step 3: Static repair until compilable
            for static_iter in range(MAX_STATIC_REPAIR_PER_CYCLE):
                compile_ok, compile_error = compile_decompiled(current_code, language, output_dir)
                
                if compile_ok:
                    break
                
                stats['static_repairs'] += 1
                print(f"  [Static Repair {stats['static_repairs']}] Fixing compilation errors...")
                
                repair_prompt = get_static_repair_prompt(current_code, compile_error, language)
                current_code = llm_interface.generate(repair_prompt)
            
            # Check if we got compilable code
            compile_ok, _ = compile_decompiled(current_code, language, output_dir)
            if not compile_ok:
                print(f"  [!] Still not compilable after {MAX_STATIC_REPAIR_PER_CYCLE} attempts")
                continue
            
            print(f"  [3/4] Code compiles successfully (iteration {iteration+1})")
            
            # Step 4: VexHelix verification
            stats['vexhelix_calls'] += 1
            print(f"  [4/4] Calling VexHelix (call #{stats['vexhelix_calls']})...")
            
            vexhelix_result = call_vexhelix(
                binary_path=original_binary,
                decompiled_code=current_code,
                function_name="func0",
                language=language,
                num_args=3
            )
            
            status = vexhelix_result.get('status', 'error')
            print(f"    VexHelix result: {status}")
            
            # Check result
            if status == 'equivalent':
                print(f"  ✓ EQUIVALENT after {iteration+1} iteration(s)!")
                return SampleResult(
                    index=idx,
                    language=language,
                    success=True,
                    final_status="equivalent",
                    iterations=iteration + 1,
                    vexhelix_calls=stats['vexhelix_calls'],
                    static_repairs=stats['static_repairs'],
                    duration=time.time() - start_time,
                    final_code=current_code
                )
            
            elif status == 'timeout':
                print(f"  ~ Timeout")
                return SampleResult(
                    index=idx,
                    language=language,
                    success=False,
                    final_status="timeout",
                    iterations=iteration + 1,
                    vexhelix_calls=stats['vexhelix_calls'],
                    static_repairs=stats['static_repairs'],
                    duration=time.time() - start_time,
                    error_message="VexHelix execution timeout"
                )
            
            elif status == 'error':
                # Check if it's a compilation error on VexHelix side
                comp_error = vexhelix_result.get('compilation_error')
                if comp_error:
                    print(f"  [VexHelix Compile Error] Retrying with static repair...")
                    stats['static_repairs'] += 1
                    repair_prompt = get_static_repair_prompt(current_code, comp_error, language)
                    current_code = llm_interface.generate(repair_prompt)
                    continue
                else:
                    print(f"  ✗ VexHelix error: {vexhelix_result.get('message', 'Unknown')[:100]}")
                    return SampleResult(
                        index=idx,
                        language=language,
                        success=False,
                        final_status="error",
                        iterations=iteration + 1,
                        vexhelix_calls=stats['vexhelix_calls'],
                        static_repairs=stats['static_repairs'],
                        duration=time.time() - start_time,
                        error_message=vexhelix_result.get('message', 'Unknown error')
                    )
            
            elif status == 'different':
                # Semantic repair needed
                print(f"  [Semantic Repair] Fixing logical errors...")
                semantic_prompt = get_semantic_repair_prompt(
                    original_ghidra=ghidra_code,
                    current_code=current_code,
                    vexhelix_result=vexhelix_result,
                    language=language
                )
                current_code = llm_interface.generate(semantic_prompt)
        
        # Max iterations reached
        return SampleResult(
            index=idx,
            language=language,
            success=False,
            final_status="max_iterations",
            iterations=MAX_REPAIR_ITERATIONS,
            vexhelix_calls=stats['vexhelix_calls'],
            static_repairs=stats['static_repairs'],
            duration=time.time() - start_time,
            error_message=f"Max iterations ({MAX_REPAIR_ITERATIONS}) reached"
        )
    
    except Exception as e:
        return SampleResult(
            index=idx,
            language=language,
            success=False,
            final_status="exception",
            iterations=stats['iterations'],
            vexhelix_calls=stats['vexhelix_calls'],
            static_repairs=stats['static_repairs'],
            duration=time.time() - start_time,
            error_message=str(e)
        )
    finally:
        # Cleanup
        if output_dir.exists():
            shutil.rmtree(output_dir, ignore_errors=True)


def run_batch_test(
    c_samples: List[Dict],
    cpp_samples: List[Dict],
    concurrent: bool = True
) -> BatchResult:
    """
    Run the full pipeline test on a batch of samples.
    
    Args:
        c_samples: List of C samples to process
        cpp_samples: List of C++ samples to process
        concurrent: Whether to process samples concurrently
    """
    all_samples = c_samples + cpp_samples
    start_time = time.time()
    
    print(f"\n{'='*70}")
    print(f"Starting Full Pipeline Test")
    print(f"{'='*70}")
    print(f"C samples: {len(c_samples)}")
    print(f"C++ samples: {len(cpp_samples)}")
    print(f"Total: {len(all_samples)}")
    print(f"Concurrent: {concurrent} (workers: {CONCURRENT_WORKERS})")
    print(f"{'='*70}\n")
    
    results = []
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        if concurrent:
            with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
                futures = {
                    executor.submit(process_sample, sample, temp_path): sample
                    for sample in all_samples
                }
                
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)
                    
                    # Print progress
                    status_symbol = "✓" if result.success else "✗"
                    print(f"[{status_symbol}] Sample {result.index} ({result.language}): {result.final_status} ({result.duration:.1f}s)")
        else:
            for sample in all_samples:
                result = process_sample(sample, temp_path)
                results.append(result)
    
    total_time = time.time() - start_time
    
    # Aggregate results
    batch_result = BatchResult(
        total=len(results),
        equivalent=sum(1 for r in results if r.final_status == "equivalent"),
        different=sum(1 for r in results if r.final_status == "different"),
        errors=sum(1 for r in results if r.final_status in ["error", "exception"]),
        timeouts=sum(1 for r in results if r.final_status == "timeout"),
        compile_failures=sum(1 for r in results if r.final_status == "compile_failed"),
        total_time=total_time,
        results=results
    )
    
    return batch_result


def print_summary(batch_result: BatchResult):
    """Print summary of batch results."""
    print(f"\n{'='*70}")
    print(f"TEST SUMMARY")
    print(f"{'='*70}")
    print(f"Total samples: {batch_result.total}")
    print(f"Equivalent:    {batch_result.equivalent} ({100*batch_result.equivalent/batch_result.total:.1f}%)")
    print(f"Different:     {batch_result.different}")
    print(f"Errors:        {batch_result.errors}")
    print(f"Timeouts:      {batch_result.timeouts}")
    print(f"Compile fail:  {batch_result.compile_failures}")
    print(f"Total time:    {batch_result.total_time:.1f}s")
    print(f"Avg time/sample: {batch_result.total_time/batch_result.total:.1f}s")
    print(f"{'='*70}")
    
    # Language breakdown
    c_results = [r for r in batch_result.results if r.language == 'c']
    cpp_results = [r for r in batch_result.results if r.language == 'cpp']
    
    c_equiv = sum(1 for r in c_results if r.final_status == "equivalent")
    cpp_equiv = sum(1 for r in cpp_results if r.final_status == "equivalent")
    
    print(f"\nLanguage Breakdown:")
    print(f"  C:   {c_equiv}/{len(c_results)} equivalent")
    print(f"  C++: {cpp_equiv}/{len(cpp_results)} equivalent")
    
    # List failures
    failures = [r for r in batch_result.results if not r.success]
    if failures:
        print(f"\nFailed Samples:")
        for r in failures:
            print(f"  [{r.index}] {r.language}: {r.final_status} - {r.error_message or 'No message'}") 


def main():
    """Main entry point."""
    print("MissionDecompile V6 - Full Pipeline Test")
    print("="*50)
    
    # Check VexHelix
    if not check_vexhelix_health():
        print("ERROR: VexHelix API not available!")
        print("Start VexHelix server with: python -m vexhelix.api.server --port 8001")
        sys.exit(1)
    
    # Load dataset
    if not DATASET_PATH.exists():
        print(f"ERROR: Dataset not found: {DATASET_PATH}")
        sys.exit(1)
    
    with open(DATASET_PATH) as f:
        dataset = json.load(f)
    
    # Split by language
    c_samples = [d for d in dataset if d['language'] == 'c']
    cpp_samples = [d for d in dataset if d['language'] == 'cpp']
    
    print(f"Dataset: {len(c_samples)} C, {len(cpp_samples)} C++")
    
    # Select samples (first N from each)
    test_c_samples = c_samples[:NUM_C_SAMPLES]
    test_cpp_samples = cpp_samples[:NUM_CPP_SAMPLES]
    
    # Run test
    batch_result = run_batch_test(test_c_samples, test_cpp_samples, concurrent=True)
    
    # Print summary
    print_summary(batch_result)
    
    # Save results
    results_file = OUTPUT_DIR / "test_results.json"
    with open(results_file, 'w') as f:
        json.dump({
            'total': batch_result.total,
            'equivalent': batch_result.equivalent,
            'errors': batch_result.errors,
            'timeouts': batch_result.timeouts,
            'total_time': batch_result.total_time,
            'results': [
                {
                    'index': r.index,
                    'language': r.language,
                    'success': r.success,
                    'final_status': r.final_status,
                    'iterations': r.iterations,
                    'vexhelix_calls': r.vexhelix_calls,
                    'static_repairs': r.static_repairs,
                    'duration': r.duration,
                    'error_message': r.error_message
                }
                for r in batch_result.results
            ]
        }, f, indent=2)
    
    print(f"\nResults saved to: {results_file}")
    
    # Return exit code based on success rate
    success_rate = batch_result.equivalent / batch_result.total
    if success_rate >= 0.8:
        print("\n✓ TEST PASSED (>=80% equivalent)")
        sys.exit(0)
    else:
        print(f"\n✗ TEST FAILED ({success_rate*100:.0f}% equivalent, need >=80%)")
        sys.exit(1)


if __name__ == "__main__":
    main()
