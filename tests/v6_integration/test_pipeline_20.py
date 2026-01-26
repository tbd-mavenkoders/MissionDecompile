#!/usr/bin/env python3
"""
V6 Pipeline Test - 10 C + 10 C++ samples
Tests full pipeline: Ghidra pseudo -> LLM -> VexHelix verification loop
Goal: VexHelix should return "equivalent" for all samples (0 errors)

Uses streaming pool: samples start immediately when slots free up (no batch-wait).
Each sample writes to its own result file -> consolidated at end.
"""

import sys
import json
import time
import tempfile
import subprocess
import requests
import yaml
import threading
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
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
MAX_REPAIR_ITERS = 7
POOL_SIZE = 16  # Max concurrent workers
MAX_STAGNANT_ITERS = 4  # Early exit if divergences don't improve

# Token limit safety (GPT-OSS-20B: 130K context)
MAX_ERROR_CHARS = 2000  # ~500 tokens
MAX_CODE_CHARS = 12000  # ~3000 tokens

compiler = Compiler()
llm = create_llm_interface(
    provider=config["llm"]["vllm_provider"],
    model_name=config["llm"]["vllm_model_name"],
    base_url=config["llm"]["vllm_base_url"]
)

# Thread-safe progress tracking
print_lock = threading.Lock()
active_count = 0
completed_count = 0

@dataclass
class Result:
    idx: int
    lang: str
    status: str  # equivalent, different, error, timeout, compile_fail
    iters: int
    vexhelix_calls: int
    duration: float
    error: Optional[str] = None

def call_vexhelix(bin_path: Path, code: str, func_name: str, lang: str, retries: int = 3) -> Dict:
    """Call VexHelix API with retry logic for transient failures"""
    last_error = None
    for attempt in range(retries):
        try:
            with open(bin_path, 'rb') as f:
                resp = requests.post(
                    f"{VEXHELIX_URL}/verify",
                    data={'decompiled_code': code, 'function_name': func_name, 
                          'language': lang, 'num_args': '3', 'loop_bound': '5', 'timeout': '180'},
                    files={'original_binary': (bin_path.name, f, 'application/octet-stream')},
                    timeout=200
                )
            if resp.status_code == 200:
                return resp.json()
            else:
                last_error = f"HTTP {resp.status_code}"
                if resp.status_code >= 500:  # Server error, retry
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue
                return {'status': 'error', 'message': last_error}
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_error = str(e)[:200]
            if attempt < retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff: 1s, 2s, 4s
                continue
        except Exception as e:
            return {'status': 'error', 'message': str(e)[:200]}
    return {'status': 'error', 'message': f"Failed after {retries} retries: {last_error}"}

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

def get_initial_prompt(ghidra: str, asm: str, lang: str) -> str:
    """Initial prompt with both Ghidra and assembly - assembly is ground truth."""
    truncated_asm = asm[:5000] if asm else ""
    if len(asm) > 5000:
        truncated_asm += "\n; ... (truncated)"
    
    return f"""{config['prompts']['system_prompt']}

IMPORTANT: Ghidra's decompilation may have errors. The assembly shows the true behavior.
Common Ghidra mistakes: wrong return types (void instead of float), missing float operations, empty loop bodies.
If Ghidra shows 'void' but assembly uses xmm0 for return, the function returns float/double.

Assembly (ground truth):
```asm
{truncated_asm}
```

Ghidra decompilation (may be incorrect):
```{lang}
{ghidra}
```"""

def get_repair_prompt(code: str, errors: str, lang: str) -> str:
    truncated_errors = errors[:MAX_ERROR_CHARS]
    if len(errors) > MAX_ERROR_CHARS:
        truncated_errors += "\n... (truncated)"
    truncated_code = code[:MAX_CODE_CHARS]
    if len(code) > MAX_CODE_CHARS:
        truncated_code += "\n// ... (truncated)"
    return f"{config['prompts']['compilation_error']}\n\n```{lang}\n{truncated_code}\n```\n\nErrors:\n{truncated_errors}"

def get_semantic_prompt(ghidra: str, asm: str, code: str, vex_result: Dict, lang: str) -> str:
    """Generate robust semantic repair prompt - assembly is ground truth, Ghidra is unreliable."""
    
    # Truncate assembly but keep more of it (it's the ground truth!)
    truncated_asm = asm[:6000] if asm else ""
    if len(asm) > 6000:
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
```{lang}
{ghidra}
```

YOUR CURRENT CODE (WRONG - produces incorrect output):
```{lang}
{code}
```

VERIFICATION RESULT: DIFFERENT (your code doesn't match the binary's behavior)
"""
    
    # Format divergences with clear explanation
    if vex_result.get('divergences'):
        prompt += "\nCOUNTEREXAMPLES (inputs where your code gives wrong answer):\n"
        for i, div in enumerate(vex_result['divergences'][:5]):  # Show more divergences
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

def process_sample(sample: Dict, temp_base: Path, results_dir: Path) -> Result:
    """Process single sample through full pipeline with stagnation detection.
    Writes result to individual file for thread-safe consolidation."""
    global active_count, completed_count
    
    start = time.time()
    idx, lang = sample['index'], sample['language']
    out_dir = temp_base / f"s{idx}"
    out_dir.mkdir(exist_ok=True)
    
    # Debug log for stagnation analysis
    debug_log = {
        'idx': idx, 'lang': lang,
        'original_func': sample.get('func', '')[:500],
        'ghidra_pseudo': sample.get('ghidra_pseudo', '')[:1000],
        'iterations': []
    }
    
    stats = {'iters': 0, 'vex_calls': 0}
    
    # Track divergence improvement
    best_divergences = float('inf')
    stagnant_count = 0
    
    with print_lock:
        active_count += 1
        print(f"  [START] {idx} ({lang}) - active: {active_count}", flush=True)
    
    try:
        # 1. Compile original
        orig_code = sample['func_dep'] + sample['func']
        orig_bin = compile_original(orig_code, lang, out_dir)
        if not orig_bin:
            return _finish(Result(idx, lang, "compile_fail", 0, 0, time.time()-start, "Original compile failed"), results_dir, debug_log)
        
        # 2. Initial LLM call (with both Ghidra and assembly)
        ghidra = sample['ghidra_pseudo']
        asm = sample.get('asm', '')
        code = llm.generate(get_initial_prompt(ghidra, asm, lang))
        
        # 3. Repair loop
        for it in range(MAX_REPAIR_ITERS):
            stats['iters'] = it + 1
            iter_debug = {'iter': it + 1, 'code_snippet': code[:300]}
            
            # Static repair (up to 3 attempts)
            ok = False
            for _ in range(3):
                ok, err = compile_decompiled(code, lang, out_dir)
                if ok:
                    break
                code = llm.generate(get_repair_prompt(code, err, lang))
            
            if not ok:
                iter_debug['status'] = 'compile_fail'
                debug_log['iterations'].append(iter_debug)
                continue  # Still can't compile, try next iteration
            
            # VexHelix verification
            stats['vex_calls'] += 1
            vex = call_vexhelix(orig_bin, code, "func0", lang)
            status = vex.get('status', 'error')
            
            iter_debug['vex_status'] = status
            
            if status == 'equivalent':
                iter_debug['status'] = 'equivalent'
                debug_log['iterations'].append(iter_debug)
                return _finish(Result(idx, lang, "equivalent", stats['iters'], stats['vex_calls'], time.time()-start), results_dir, debug_log)
            elif status == 'timeout':
                iter_debug['status'] = 'timeout'
                debug_log['iterations'].append(iter_debug)
                return _finish(Result(idx, lang, "timeout", stats['iters'], stats['vex_calls'], time.time()-start), results_dir, debug_log)
            elif status == 'error':
                comp_err = vex.get('compilation_error')
                if comp_err:
                    iter_debug['status'] = 'vex_compile_error'
                    iter_debug['error'] = comp_err[:200]
                    debug_log['iterations'].append(iter_debug)
                    code = llm.generate(get_repair_prompt(code, comp_err[:500], lang))
                    continue
                iter_debug['status'] = 'vex_error'
                iter_debug['error'] = vex.get('message', '')[:200]
                debug_log['iterations'].append(iter_debug)
                return _finish(Result(idx, lang, "error", stats['iters'], stats['vex_calls'], time.time()-start, vex.get('message', '')[:200]), results_dir, debug_log)
            elif status == 'different':
                # Track divergence improvement
                divs = vex.get('divergences', [])
                div_count = len(divs)
                
                # Log divergence details for debugging
                iter_debug['div_count'] = div_count
                iter_debug['divergences'] = []
                for d in divs[:3]:  # First 3 divergences
                    div_info = {}
                    if d.get('inputs'):
                        div_info['inputs'] = [{'name': i.get('name'), 'value': i.get('value')} for i in d['inputs'][:2]]
                    if d.get('orig_output'):
                        div_info['expected'] = d['orig_output'].get('value')
                    if d.get('dec_output'):
                        div_info['got'] = d['dec_output'].get('value')
                    iter_debug['divergences'].append(div_info)
                
                if div_count < best_divergences:
                    best_divergences = div_count
                    stagnant_count = 0
                    iter_debug['status'] = 'improved'
                else:
                    stagnant_count += 1
                    iter_debug['status'] = f'stagnant_{stagnant_count}'
                    if stagnant_count >= MAX_STAGNANT_ITERS:
                        debug_log['iterations'].append(iter_debug)
                        debug_log['final_code'] = code
                        return _finish(Result(idx, lang, f"stagnant_{div_count}div", stats['iters'], stats['vex_calls'], 
                                      time.time()-start, f"Stuck at {div_count} divergences"), results_dir, debug_log)
                
                debug_log['iterations'].append(iter_debug)
                
                # Include assembly in semantic repair prompt (crucial for fixing logic)
                asm = sample.get('asm', '')
                code = llm.generate(get_semantic_prompt(ghidra, asm, code, vex, lang))
        
        debug_log['final_code'] = code
        return _finish(Result(idx, lang, "max_iters", stats['iters'], stats['vex_calls'], time.time()-start), results_dir, debug_log)
    
    except Exception as e:
        debug_log['exception'] = str(e)
        return _finish(Result(idx, lang, "error", stats['iters'], stats['vex_calls'], time.time()-start, str(e)[:200]), results_dir, debug_log)

def _finish(result: Result, results_dir: Path, debug_log: dict = None) -> Result:
    """Write result to individual file and update progress."""
    global active_count, completed_count
    
    # Write to individual result file (thread-safe, no conflicts)
    result_file = results_dir / f"result_{result.idx}.json"
    with open(result_file, 'w') as f:
        json.dump(asdict(result), f)
    
    # Write debug log for non-equivalent results (helps diagnose stagnation)
    if debug_log and result.status != "equivalent":
        debug_file = results_dir / f"debug_{result.idx}.json"
        with open(debug_file, 'w') as f:
            json.dump(debug_log, f, indent=2)
    
    with print_lock:
        active_count -= 1
        completed_count += 1
        sym = "✓" if result.status == "equivalent" else "✗"
        print(f"[{sym}] {result.idx} ({result.lang}): {result.status} ({result.iters}it, {result.vexhelix_calls}vex, {result.duration:.1f}s) | done: {completed_count}, active: {active_count}", flush=True)
    
    return result

def main():
    global active_count, completed_count
    
    print("V6 Pipeline Test - 10 C + 10 C++ (Streaming Pool)")
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
    
    # Select by actual index values: 11-20 (C++) and 667-676 (C)
    by_idx = {d['index']: d for d in data}
    cpp_samples = [by_idx[i] for i in range(11, 21) if i in by_idx]  # indices 11-20 (C++)
    c_samples = [by_idx[i] for i in range(667, 677) if i in by_idx]  # indices 667-676 (C)
    all_samples = c_samples + cpp_samples
    
    print(f"Testing C indices 667-676 ({len(c_samples)}) + C++ indices 11-20 ({len(cpp_samples)})")
    print(f"Pool size: {POOL_SIZE} concurrent workers")
    print("="*50)
    
    start_all = time.time()
    
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        
        # True streaming pool using ThreadPoolExecutor
        # Each completed task immediately frees a slot for the next
        
        executor = ThreadPoolExecutor(max_workers=POOL_SIZE)
        try:
            # Submit all tasks - executor handles queuing internally
            futures = {executor.submit(process_sample, s, tmp_path, results_dir): s['index'] for s in all_samples}
            
            # Process completions as they arrive (true streaming)
            for future in as_completed(futures):
                # Result already written to file and printed in _finish()
                # Just handle any exceptions
                try:
                    future.result()
                except Exception as e:
                    idx = futures[future]
                    print(f"[ERROR] {idx}: {e}")
        finally:
            # Shutdown immediately without waiting (all futures already completed)
            executor.shutdown(wait=False, cancel_futures=True)
        
        print(f"\n[DEBUG] All {len(futures)} futures completed, consolidating results...", flush=True)
        
        # Consolidate results from individual files
        results = []
        for result_file in results_dir.glob("result_*.json"):
            with open(result_file) as f:
                r = json.load(f)
                results.append(Result(**r))
        
        print(f"[DEBUG] Loaded {len(results)} results from temp dir", flush=True)
        
        # Copy debug logs to permanent location
        out_dir = SCRIPT_DIR / "outputs"
        out_dir.mkdir(exist_ok=True)
        debug_out_dir = out_dir / "debug_logs"
        debug_out_dir.mkdir(exist_ok=True)
        
        for debug_file in results_dir.glob("debug_*.json"):
            shutil.copy(debug_file, debug_out_dir / debug_file.name)
        
        print(f"[DEBUG] Debug logs saved to {debug_out_dir}", flush=True)
    
    total_time = time.time() - start_all
    
    # Summary
    print("\n" + "="*50)
    print("SUMMARY")
    print("="*50)
    equiv = sum(1 for r in results if r.status == "equivalent")
    c_equiv = sum(1 for r in results if r.status == "equivalent" and r.lang == "c")
    cpp_equiv = sum(1 for r in results if r.status == "equivalent" and r.lang == "cpp")
    stagnant = sum(1 for r in results if r.status.startswith("stagnant"))
    
    print(f"Equivalent: {equiv}/{len(results)} ({100*equiv/len(results):.0f}%)")
    print(f"  C: {c_equiv}/10, C++: {cpp_equiv}/10")
    print(f"Stagnant (early exit): {stagnant}")
    print(f"Errors: {sum(1 for r in results if r.status == 'error')}")
    print(f"Timeouts: {sum(1 for r in results if r.status == 'timeout')}")
    print(f"Max iters: {sum(1 for r in results if r.status == 'max_iters')}")
    print(f"Total time: {total_time:.1f}s ({total_time/len(results):.1f}s/sample)")
    
    # Save results
    out_file = SCRIPT_DIR / "outputs" / "test_results.json"
    out_file.parent.mkdir(exist_ok=True)
    with open(out_file, 'w') as f:
        json.dump([asdict(r) for r in results], f, indent=2)
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
