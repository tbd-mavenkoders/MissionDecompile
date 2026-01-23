#!/usr/bin/env python3
"""
V6 Pipeline Test - 10 C + 10 C++ samples
Tests full pipeline: Ghidra pseudo -> LLM -> VexHelix verification loop
Goal: VexHelix should return "equivalent" for all samples (0 errors)
"""

import sys
import json
import time
import tempfile
import subprocess
import requests
import yaml
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Optional

# Setup paths
SCRIPT_DIR = Path(__file__).resolve().parent
MISSION_DIR = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(MISSION_DIR))

from utils.llm_interface import create_llm_interface
from utils.compile import Compiler, OptimizationLevel

# Load config
CONFIG_PATH = MISSION_DIR / "config.yaml"
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

DATASET_PATH = Path(config["humaneval"]["corpus_path"]) / "humaneval-decompile.json"
VEXHELIX_URL = "http://127.0.0.1:8001"
MAX_REPAIR_ITERS = 10
CONCURRENT_WORKERS = 8

# Token limit safety (GPT-OSS-20B: 130K context)
MAX_ERROR_CHARS = 2000  # ~500 tokens
MAX_CODE_CHARS = 12000  # ~3000 tokens

compiler = Compiler()
llm = create_llm_interface(
    provider=config["llm"]["vllm_provider"],
    model_name=config["llm"]["vllm_model_name"],
    base_url=config["llm"]["vllm_base_url"]
)

@dataclass
class Result:
    idx: int
    lang: str
    status: str  # equivalent, different, error, timeout, compile_fail
    iters: int
    vexhelix_calls: int
    duration: float
    error: Optional[str] = None

def call_vexhelix(bin_path: Path, code: str, func_name: str, lang: str) -> Dict:
    """Call VexHelix API"""
    try:
        with open(bin_path, 'rb') as f:
            resp = requests.post(
                f"{VEXHELIX_URL}/verify",
                data={'decompiled_code': code, 'function_name': func_name, 
                      'language': lang, 'num_args': '3', 'loop_bound': '5', 'timeout': '120'},
                files={'original_binary': (bin_path.name, f, 'application/octet-stream')},
                timeout=150
            )
        return resp.json() if resp.status_code == 200 else {'status': 'error', 'message': f"HTTP {resp.status_code}"}
    except Exception as e:
        return {'status': 'error', 'message': str(e)[:200]}

def compile_original(code: str, lang: str, out_dir: Path) -> Optional[Path]:
    """Compile original code"""
    ext = ".cpp" if lang == "cpp" else ".c"
    src = out_dir / f"orig{ext}"
    bin_path = out_dir / "orig.bin"
    src.write_text(code)
    status, _ = compiler.compile_source(str(src), str(bin_path), is_cpp=(lang=="cpp"), c_flag=True, opt=OptimizationLevel.O0)
    return bin_path if status and bin_path.exists() else None

def compile_decompiled(code: str, lang: str, out_dir: Path) -> tuple:
    """Compile decompiled code, return (success, error_msg)"""
    ext = ".cpp" if lang == "cpp" else ".c"
    src = out_dir / f"dec{ext}"
    bin_path = out_dir / "dec.bin"
    src.write_text(code)
    cc = "g++" if lang == "cpp" else "gcc"
    r = subprocess.run([cc, "-O0", "-fno-stack-protector", "-w", str(src), "-o", str(bin_path), "-lm"],
                       capture_output=True, text=True, timeout=30)
    return (True, "") if r.returncode == 0 else (False, r.stderr[:500])

def get_initial_prompt(ghidra: str, lang: str) -> str:
    return f"{config['prompts']['system_prompt']}\n\n```{lang}\n{ghidra}\n```"

def get_repair_prompt(code: str, errors: str, lang: str) -> str:
    truncated_errors = errors[:MAX_ERROR_CHARS]
    if len(errors) > MAX_ERROR_CHARS:
        truncated_errors += "\n... (truncated)"
    truncated_code = code[:MAX_CODE_CHARS]
    if len(code) > MAX_CODE_CHARS:
        truncated_code += "\n// ... (truncated)"
    return f"{config['prompts']['compilation_error']}\n\n```{lang}\n{truncated_code}\n```\n\nErrors:\n{truncated_errors}"

def get_semantic_prompt(ghidra: str, code: str, vex_result: Dict, lang: str) -> str:
    prompt = f"{config['prompts']['semantic_repair']}\n\nOriginal Ghidra:\n```{lang}\n{ghidra}\n```\n\n"
    prompt += f"Current (WRONG):\n```{lang}\n{code}\n```\n\nVexHelix: DIFFERENT\n"
    if vex_result.get('divergences'):
        prompt += f"Divergences: {str(vex_result['divergences'][:2])[:300]}\n"
    return prompt

def process_sample(sample: Dict, temp_base: Path) -> Result:
    """Process single sample through full pipeline"""
    start = time.time()
    idx, lang = sample['index'], sample['language']
    out_dir = temp_base / f"s{idx}"
    out_dir.mkdir(exist_ok=True)
    
    stats = {'iters': 0, 'vex_calls': 0}
    
    # 1. Compile original
    orig_code = sample['func_dep'] + sample['func']
    orig_bin = compile_original(orig_code, lang, out_dir)
    if not orig_bin:
        return Result(idx, lang, "compile_fail", 0, 0, time.time()-start, "Original compile failed")
    
    # 2. Initial LLM call
    ghidra = sample['ghidra_pseudo']
    code = llm.generate(get_initial_prompt(ghidra, lang))
    
    # 3. Repair loop
    for it in range(MAX_REPAIR_ITERS):
        stats['iters'] = it + 1
        
        # Static repair (up to 3 attempts)
        for _ in range(3):
            ok, err = compile_decompiled(code, lang, out_dir)
            if ok:
                break
            code = llm.generate(get_repair_prompt(code, err, lang))
        
        if not ok:
            continue  # Still can't compile, try next iteration
        
        # VexHelix verification
        stats['vex_calls'] += 1
        vex = call_vexhelix(orig_bin, code, "func0", lang)
        status = vex.get('status', 'error')
        
        if status == 'equivalent':
            return Result(idx, lang, "equivalent", stats['iters'], stats['vex_calls'], time.time()-start)
        elif status == 'timeout':
            return Result(idx, lang, "timeout", stats['iters'], stats['vex_calls'], time.time()-start)
        elif status == 'error':
            comp_err = vex.get('compilation_error')
            if comp_err:
                code = llm.generate(get_repair_prompt(code, comp_err[:500], lang))
                continue
            return Result(idx, lang, "error", stats['iters'], stats['vex_calls'], time.time()-start, vex.get('message', '')[:200])
        elif status == 'different':
            code = llm.generate(get_semantic_prompt(ghidra, code, vex, lang))
    
    return Result(idx, lang, "max_iters", stats['iters'], stats['vex_calls'], time.time()-start)

def main():
    print("V6 Pipeline Test - 10 C + 10 C++")
    print("="*50)
    
    # Check VexHelix
    try:
        r = requests.get(f"{VEXHELIX_URL}/health", timeout=5)
        if r.status_code != 200:
            print("ERROR: VexHelix not healthy")
            return
        print(f"VexHelix: {r.json().get('status')}")
    except:
        print("ERROR: VexHelix not reachable")
        return
    
    # Load dataset
    with open(DATASET_PATH) as f:
        data = json.load(f)
    
    c_samples = [d for d in data if d['language'] == 'c'][:10]
    cpp_samples = [d for d in data if d['language'] == 'cpp'][:10]
    all_samples = c_samples + cpp_samples
    
    print(f"Testing {len(c_samples)} C + {len(cpp_samples)} C++ samples")
    print("="*50)
    
    results = []
    start_all = time.time()
    
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        
        with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as ex:
            futures = {ex.submit(process_sample, s, tmp_path): s for s in all_samples}
            for f in as_completed(futures):
                r = f.result()
                results.append(r)
                sym = "✓" if r.status == "equivalent" else "✗"
                print(f"[{sym}] {r.idx} ({r.lang}): {r.status} ({r.iters}it, {r.vexhelix_calls}vex, {r.duration:.1f}s)")
    
    total_time = time.time() - start_all
    
    # Summary
    print("\n" + "="*50)
    print("SUMMARY")
    print("="*50)
    equiv = sum(1 for r in results if r.status == "equivalent")
    c_equiv = sum(1 for r in results if r.status == "equivalent" and r.lang == "c")
    cpp_equiv = sum(1 for r in results if r.status == "equivalent" and r.lang == "cpp")
    
    print(f"Equivalent: {equiv}/{len(results)} ({100*equiv/len(results):.0f}%)")
    print(f"  C: {c_equiv}/10, C++: {cpp_equiv}/10")
    print(f"Errors: {sum(1 for r in results if r.status == 'error')}")
    print(f"Timeouts: {sum(1 for r in results if r.status == 'timeout')}")
    print(f"Total time: {total_time:.1f}s ({total_time/len(results):.1f}s/sample)")
    
    # Save results
    out_file = SCRIPT_DIR / "outputs" / "test_results.json"
    out_file.parent.mkdir(exist_ok=True)
    with open(out_file, 'w') as f:
        json.dump([{'idx': r.idx, 'lang': r.lang, 'status': r.status, 'iters': r.iters,
                    'vex_calls': r.vexhelix_calls, 'duration': r.duration, 'error': r.error} 
                   for r in results], f, indent=2)
    print(f"\nResults: {out_file}")
    
    if equiv >= 16:  # 80% pass
        print("\n✓ TEST PASSED")
    else:
        print(f"\n✗ TEST FAILED (need 80%, got {100*equiv/len(results):.0f}%)")
        print("\nFailed samples:")
        for r in results:
            if r.status != "equivalent":
                print(f"  [{r.idx}] {r.lang}: {r.status} - {r.error or ''}")

if __name__ == "__main__":
    main()
