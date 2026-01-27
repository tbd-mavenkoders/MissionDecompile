#!/usr/bin/env python3
"""
Pipeline Test for V6 + VexHelix

Runs 10 C + 10 C++ samples through the FULL pipeline:
1. Compile original -> binary
2. LLM generates code from Ghidra pseudo
3. VexHelix verifies equivalence
4. Loop until equivalent or max iterations

Goal: VexHelix should NOT return errors, should return "equivalent" eventually.
"""

import sys
import json
import time
import tempfile
import subprocess
import requests
import yaml
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional

# Setup paths
SCRIPT_DIR = Path(__file__).resolve().parent
MISSION_DIR = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(MISSION_DIR))

from utils.llm_interface import create_llm_interface
from utils.compile import Compiler, OptimizationLevel

# Load config
with open(MISSION_DIR / "config.yaml") as f:
    config = yaml.safe_load(f)

# Config
VEXHELIX_URL = "http://127.0.0.1:8001"
DATASET_PATH = Path(config["humaneval"]["corpus_path"]) / "humaneval-decompile.json"
NUM_SAMPLES = 10  # 10 C + 10 C++
MAX_ITERATIONS = 8
VEXHELIX_TIMEOUT = 120

# Initialize
compiler = Compiler()
llm = create_llm_interface(
    provider=config["llm"]["vllm_provider"],
    model_name=config["llm"]["vllm_model_name"],
    base_url=config["llm"]["vllm_base_url"]
)


@dataclass
class Result:
    index: int
    lang: str
    status: str  # equivalent, different, error, timeout, compile_fail
    iterations: int
    time_sec: float
    error: Optional[str] = None


def call_vexhelix(binary_path: Path, code: str, func: str, lang: str) -> Dict:
    """Call VexHelix API."""
    try:
        with open(binary_path, 'rb') as f:
            resp = requests.post(
                f"{VEXHELIX_URL}/verify",
                data={'decompiled_code': code, 'function_name': func, 
                      'language': lang, 'num_args': '3', 'timeout': str(VEXHELIX_TIMEOUT)},
                files={'original_binary': (binary_path.name, f, 'application/octet-stream')},
                timeout=VEXHELIX_TIMEOUT + 30
            )
        return resp.json() if resp.status_code == 200 else {'status': 'error', 'message': resp.text[:200]}
    except Exception as e:
        return {'status': 'error', 'message': str(e)[:200]}


def compile_original(code: str, lang: str, out_dir: Path) -> Optional[Path]:
    """Compile original code."""
    ext = ".cpp" if lang == "cpp" else ".c"
    src = out_dir / f"orig{ext}"
    bin_path = out_dir / "orig.bin"
    src.write_text(code)
    
    ok, _ = compiler.compile_source(src, bin_path, OptimizationLevel.O0, is_cpp=(lang=="cpp"), c_flag=True)
    return bin_path if ok and bin_path.exists() else None


def compile_decompiled(code: str, lang: str, out_dir: Path) -> tuple:
    """Try compile decompiled code. Returns (success, error_msg)."""
    ext = ".cpp" if lang == "cpp" else ".c"
    src = out_dir / f"dec{ext}"
    bin_path = out_dir / "dec.bin"
    src.write_text(code)
    
    cc = "g++" if lang == "cpp" else "gcc"
    r = subprocess.run([cc, "-O0", "-w", "-fno-stack-protector", str(src), "-o", str(bin_path), "-lm"],
                       capture_output=True, text=True, timeout=30)
    return (True, "") if r.returncode == 0 else (False, r.stderr[:500])


def get_initial_prompt(ghidra_code: str, lang: str) -> str:
    return f"{config['prompts']['system_prompt']}\n\n```{lang}\n{ghidra_code}\n```"


def get_repair_prompt(code: str, errors: str, lang: str) -> str:
    return f"{config['prompts']['compilation_error']}\n\n```{lang}\n{code}\n```\n\nErrors:\n{errors}"


def get_semantic_prompt(ghidra: str, code: str, result: Dict, lang: str) -> str:
    prompt = f"{config['prompts']['semantic_repair']}\n\nGhidra:\n```{lang}\n{ghidra}\n```\n\n"
    prompt += f"Current (WRONG):\n```{lang}\n{code}\n```\n\nVexHelix: DIFFERENT\n"
    if result.get('divergences'):
        prompt += f"Divergences: {str(result['divergences'])[:300]}\n"
    return prompt


def process_sample(sample: Dict, tmp_dir: Path) -> Result:
    """Process one sample through full pipeline."""
    start = time.time()
    idx, lang = sample['index'], sample['language']
    ghidra_code = sample['ghidra_pseudo']
    
    print(f"  [{idx}] {lang.upper()}", end=" ", flush=True)
    
    # Compile original
    orig_code = sample['func_dep'] + sample['func']
    orig_bin = compile_original(orig_code, lang, tmp_dir)
    if not orig_bin:
        print("✗ orig compile fail")
        return Result(idx, lang, "compile_fail", 0, time.time()-start, "Original failed to compile")
    
    # Initial LLM
    code = llm.generate(get_initial_prompt(ghidra_code, lang))
    
    for iteration in range(1, MAX_ITERATIONS + 1):
        # Static repair loop (max 3 tries)
        for _ in range(3):
            ok, err = compile_decompiled(code, lang, tmp_dir)
            if ok:
                break
            code = llm.generate(get_repair_prompt(code, err, lang))
        
        if not ok:
            continue  # Still can't compile, try next iteration
        
        # Call VexHelix
        result = call_vexhelix(orig_bin, code, "func0", lang)
        status = result.get('status', 'error')
        
        if status == 'equivalent':
            print(f"✓ equiv (iter {iteration})")
            return Result(idx, lang, "equivalent", iteration, time.time()-start)
        
        if status == 'error':
            comp_err = result.get('compilation_error')
            if comp_err:
                # VexHelix compile error - fix it
                code = llm.generate(get_repair_prompt(code, comp_err[:500], lang))
                continue
            print(f"✗ error: {result.get('message', '?')[:50]}")
            return Result(idx, lang, "error", iteration, time.time()-start, result.get('message', '')[:200])
        
        if status == 'timeout':
            print(f"~ timeout (iter {iteration})")
            return Result(idx, lang, "timeout", iteration, time.time()-start)
        
        if status == 'different':
            # Semantic repair
            code = llm.generate(get_semantic_prompt(ghidra_code, code, result, lang))
    
    print(f"✗ max iter")
    return Result(idx, lang, "max_iterations", MAX_ITERATIONS, time.time()-start)


def main():
    print("=" * 60)
    print("V6 + VexHelix Full Pipeline Test")
    print("=" * 60)
    
    # Check VexHelix
    try:
        r = requests.get(f"{VEXHELIX_URL}/health", timeout=5)
        if r.status_code != 200:
            print("ERROR: VexHelix not healthy!")
            return
        print(f"VexHelix: OK")
    except:
        print("ERROR: Cannot connect to VexHelix!")
        return
    
    # Load dataset
    with open(DATASET_PATH) as f:
        dataset = json.load(f)
    
    c_samples = [d for d in dataset if d['language'] == 'c'][:NUM_SAMPLES]
    cpp_samples = [d for d in dataset if d['language'] == 'cpp'][:NUM_SAMPLES]
    all_samples = c_samples + cpp_samples
    
    print(f"Testing: {len(c_samples)} C + {len(cpp_samples)} C++ = {len(all_samples)} samples")
    print("-" * 60)
    
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for i, sample in enumerate(all_samples):
            sample_dir = tmp_path / f"s{i}"
            sample_dir.mkdir()
            results.append(process_sample(sample, sample_dir))
    
    # Summary
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    
    equiv = [r for r in results if r.status == "equivalent"]
    errors = [r for r in results if r.status == "error"]
    timeouts = [r for r in results if r.status == "timeout"]
    
    print(f"Equivalent: {len(equiv)}/{len(results)} ({100*len(equiv)/len(results):.0f}%)")
    print(f"Errors:     {len(errors)}")
    print(f"Timeouts:   {len(timeouts)}")
    print(f"Total time: {sum(r.time_sec for r in results):.1f}s")
    
    c_equiv = len([r for r in equiv if r.lang == 'c'])
    cpp_equiv = len([r for r in equiv if r.lang == 'cpp'])
    print(f"\nC:   {c_equiv}/{len(c_samples)} equivalent")
    print(f"C++: {cpp_equiv}/{len(cpp_samples)} equivalent")
    
    if errors:
        print("\nErrors:")
        for r in errors[:5]:
            print(f"  [{r.index}] {r.lang}: {r.error[:80] if r.error else '?'}")
    
    # Save results
    out_file = SCRIPT_DIR / "outputs" / "pipeline_results.json"
    out_file.parent.mkdir(exist_ok=True)
    with open(out_file, 'w') as f:
        json.dump([{'index': r.index, 'lang': r.lang, 'status': r.status, 
                    'iterations': r.iterations, 'time': r.time_sec, 'error': r.error} 
                   for r in results], f, indent=2)
    print(f"\nResults saved: {out_file}")


if __name__ == "__main__":
    main()
