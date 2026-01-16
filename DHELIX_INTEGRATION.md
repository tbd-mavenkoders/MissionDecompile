# D-Helix Integration Documentation

## Overview

This document describes the integration of D-Helix semantic verification into the MissionDecompile pipeline via `batched_humaneval_collector_v2.py`.

## What Changed?

### Original Workflow (batched_humaneval_collector.py)

```
1. Compile original code → binary
2. Extract CFG/callgraph with Ghidra
3. LLM optimization loop (max 3 iterations):
   ├─ Generate summary
   ├─ Initial LLM prompt
   └─ Static repair: IF code doesn't compile
      ├─ Send errors to LLM
      ├─ Get fixed code
      └─ Retry compilation
   ✓ DONE when code compiles
```

**Problem**: Only ensures **syntactic correctness** (compiles), not **semantic correctness** (logical equivalence to binary).

---

### Enhanced Workflow (batched_humaneval_collector_v2.py)

```
1. Compile original code → binary
2. Extract CFG/callgraph with Ghidra
3. Enhanced LLM optimization loop (max 15 iterations):
   ├─ Generate summary
   ├─ Initial LLM prompt
   └─ Two-Phase Repair Loop:
      │
      ├─ PHASE 1: Static Repair (ensure compilation)
      │  └─ IF code doesn't compile:
      │     ├─ Send compilation errors to LLM
      │     ├─ Get fixed code
      │     └─ Retry (go back to Phase 1)
      │
      ├─ PHASE 2: Semantic Verification (once compiled)
      │  ├─ Call D-Helix API (binary + decompiled code)
      │  ├─ IF result = "unsat":
      │  │  └─ ✓✓✓ DONE (semantically equivalent!)
      │  └─ IF result = "sat":
      │     └─ Go to Phase 3
      │
      └─ PHASE 3: Semantic Repair (fix logical bugs)
         ├─ Extract counterexample from D-Helix
         ├─ Send to LLM with:
         │  - Original assembly
         │  - Original Ghidra code
         │  - Current (buggy) code
         │  - Counterexample
         │  - Z3 formula (partial)
         ├─ Get semantically repaired code
         └─ Go back to Phase 1 (re-check compilation)
```

**Result**: Ensures both **syntactic AND semantic correctness**.

---

## Key Components

### 1. D-Helix API Client (`call_dhelix_api`)

**Location**: Lines 82-147

**Purpose**: Communicates with D-Helix FastAPI server to verify semantic equivalence.

**Input**:
- `binary_path`: Path to original compiled binary
- `decompiled_code`: Current decompiled C/C++ code
- `function_name`: Name of function to verify

**Output**: `DHelixResult` containing:
- `success`: Whether API call succeeded
- `result`: "sat" (bug found) or "unsat" (semantically equivalent)
- `z3_formula`: Z3 SMT formula used for verification
- `counterexample`: Example input that exposes the bug (if SAT)
- `error_message`: Error details if verification failed

**Example**:
```python
result = call_dhelix_api(
    binary_path=Path("/tmp/executable"),
    decompiled_code="int add(int a, int b) { return a * b; }",  # BUG: should be a+b
    function_name="add"
)
# result.result == "sat"
# result.counterexample == {"a": 2, "b": 3}  # Shows 2*3 != 2+3
```

---

### 2. Semantic Repair Prompt Generator (`get_semantic_repair_prompt`)

**Location**: Lines 183-227

**Purpose**: Constructs LLM prompt to fix logical bugs detected by D-Helix.

**Inputs**:
- `original_asm`: Assembly code from binary
- `original_ghidra`: Initial Ghidra decompilation
- `current_code`: Current (buggy) decompiled code
- `function_summary`: Natural language description
- `dhelix_result`: D-Helix verification result (SAT)
- `language`: "c" or "cpp"

**Prompt Structure**:
```
1. Semantic repair instructions (from config.yaml)
2. Original assembly code
3. Original Ghidra decompilation
4. Current (incorrect) code
5. Function summary
6. D-Helix verification result (SAT)
7. Counterexample (if available)
8. Z3 formula (partial, to avoid context overflow)
9. Request for corrected code
```

**Example Counterexample in Prompt**:
```json
Counterexample (input values that expose the bug):
{
  "arg_0": 5,
  "arg_1": 3
}
```

This tells the LLM: "When a=5 and b=3, your code produces wrong output."

---

### 3. Enhanced Optimization Function (`get_optimized_code_v2`)

**Location**: Lines 230-388

**Purpose**: Main repair loop with static + semantic verification.

**Flow**:
```
for iteration in range(MAX_REPAIR_ITERATIONS):  # 15 iterations
    
    # Phase 1: Static Repair
    compile_success, executable = compile_code(optimized_code)
    if not compile_success:
        optimized_code = static_repair_with_llm(errors)
        continue  # Retry compilation
    
    # Phase 2: Semantic Verification
    dhelix_result = call_dhelix_api(binary, optimized_code, func_name)
    
    if dhelix_result.result == "unsat":
        return SUCCESS  # Done!
    
    # Phase 3: Semantic Repair
    optimized_code = semantic_repair_with_llm(dhelix_result)
    # Loop back to Phase 1
```

**Statistics Tracked**:
- `static_repair_iterations`: How many compilation fixes
- `semantic_repair_iterations`: How many semantic fixes
- `dhelix_calls`: Total D-Helix API calls
- `dhelix_unsat_achieved`: Did we achieve semantic equivalence?
- `final_result`: Outcome (unsat/max_iterations/dhelix_error)

---

### 4. Configuration Updates (config.yaml)

**New Prompt Added**: `semantic_repair`

**Purpose**: Instructs LLM on how to fix logical bugs using D-Helix feedback.

**Key Instructions**:
- Analyze counterexample to understand bug
- Compare current code vs assembly/Ghidra
- Fix ONLY the semantic bug
- Preserve function signature and compilation
- Output corrected code with no extra text

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     INPUT: HumanEval JSON                    │
│  [{"index": 0, "func": "...", "asm": "...", "ghidra": "..."}]│
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              STEP 1: Batch Compilation (20 parallel)        │
│   Compile original C code → Generate binaries               │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│          STEP 2: Batch Ghidra Analysis (12 parallel)        │
│   Extract CFG, call graphs, control flow                    │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│           STEP 3: Batch Summary Generation (8 parallel)     │
│   LLM generates function summaries                          │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│     STEP 4: Enhanced Optimization Loop (per function)       │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Initial LLM Prompt (fix Ghidra pseudocode)            │ │
│  └────────────────────┬───────────────────────────────────┘ │
│                       │                                      │
│  ┌────────────────────▼───────────────────────────────────┐ │
│  │ LOOP (max 15 iterations):                             │ │
│  │                                                         │ │
│  │  ┌───────────────────────────────────────────────┐   │ │
│  │  │ Phase 1: Static Repair                        │   │ │
│  │  │ • Compile code                                 │   │ │
│  │  │ • IF fails → LLM fixes compilation errors      │   │ │
│  │  │ • LOOP until compiles                          │   │ │
│  │  └───────────────────┬───────────────────────────┘   │ │
│  │                      │ compiles ✓                     │ │
│  │  ┌───────────────────▼───────────────────────────┐   │ │
│  │  │ Phase 2: Semantic Verification (D-Helix)      │   │ │
│  │  │                                                │   │ │
│  │  │  POST /verify                                  │   │ │
│  │  │  ├─ binary                                     │   │ │
│  │  │  ├─ decompiled_code                            │   │ │
│  │  │  └─ function_name                              │   │ │
│  │  │                                                │   │ │
│  │  │  Response:                                     │   │ │
│  │  │  • result: "sat" or "unsat"                    │   │ │
│  │  │  • counterexample: {...}                       │   │ │
│  │  │  • z3_formula: "..."                           │   │ │
│  │  └────────┬──────────────────────┬────────────────┘   │ │
│  │           │ unsat                │ sat                 │ │
│  │           ▼                      ▼                     │ │
│  │      ✓✓✓ DONE!        ┌──────────────────────────┐   │ │
│  │      (success)         │ Phase 3: Semantic Repair │   │ │
│  │                        │ • LLM fixes logical bug   │   │ │
│  │                        │ • Uses counterexample     │   │ │
│  │                        └──────────┬───────────────┘   │ │
│  │                                   │                    │ │
│  │                                   └──► Back to Phase 1 │ │
│  └─────────────────────────────────────────────────────┘ │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│        OUTPUT: batched_enriched_humaneval_decompile_v2.json │
│   [{                                                         │
│     "optimized_code": "...",                                 │
│     "optimization_stats": {                                  │
│       "static_repair_iterations": 2,                         │
│       "semantic_repair_iterations": 1,                       │
│       "dhelix_calls": 2,                                     │
│       "dhelix_unsat_achieved": true,                         │
│       "final_result": "unsat"                                │
│     }                                                        │
│   }]                                                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Configuration

### D-Helix API Settings

**File**: `batched_humaneval_collector_v2.py`, lines 60-62

```python
DHELIX_API_URL = "http://127.0.0.1:10012"
DHELIX_TIMEOUT = 120  # seconds
```

### Repair Limits

**File**: `batched_humaneval_collector_v2.py`, lines 64-66

```python
MAX_REPAIR_ITERATIONS = 15  # Total static + semantic repair iterations
MAX_STATIC_REPAIR_PER_CYCLE = 3  # Max static attempts before semantic check
```

---

## Output Format

### Enhanced JSON Output

Each function now includes detailed optimization statistics:

```json
{
  "index": 0,
  "language": "c",
  "original_code": "int add(int a, int b) { return a + b; }",
  "functions": [
    {
      "f_name": "add",
      "ghidra_code": "...",
      "asm": "...",
      "function_summary": "Adds two integers and returns the sum",
      "optimized_code": "int add(int a, int b) { return a + b; }",
      "optimization_status": true,
      "optimization_stats": {
        "static_repair_iterations": 1,
        "semantic_repair_iterations": 0,
        "dhelix_calls": 1,
        "dhelix_unsat_achieved": true,
        "final_result": "unsat"
      }
    }
  ]
}
```

### Statistics Interpretation

| final_result | Meaning |
|--------------|---------|
| `unsat` | ✓✓✓ Semantic equivalence achieved! |
| `max_iterations_compilable` | Max iterations reached, code compiles but semantics unknown |
| `max_iterations_not_compilable` | Max iterations reached, code doesn't compile |
| `dhelix_error` | D-Helix API error, returned compilable code without verification |

---

## Usage

### Prerequisites

1. **D-Helix API Server Running**:
   ```bash
   # On the D-Helix server (port 10012)
   cd /root/work/D-helix-fixed/fastapi_server
   source /root/.virtualenvs/angr/bin/activate
   python api_server.py
   ```

2. **MissionDecompile Environment**:
   ```bash
   cd MissionDecompile
   pip install -r requirements.txt
   ```

### Running the Enhanced Pipeline

```bash
cd MissionDecompile
python evaluator/batched_humaneval_collector_v2.py
```

### Testing D-Helix API Connectivity

```bash
curl http://127.0.0.1:10012/health
# Expected: {"status":"healthy"}
```

---

## Example: Repair Cycle

### Iteration 1: Initial Code (Compilation Error)

```c
// Ghidra output
int add(undefined4 param_1, undefined4 param_2) {
    return param_1 + param_2;  // ❌ undefined4 doesn't compile
}
```

**LLM Static Repair** → Fixes types:

```c
int add(int param_1, int param_2) {
    return param_1 + param_2;  // ✓ Compiles
}
```

### Iteration 2: D-Helix Verification

**D-Helix Call**:
```
Binary: /tmp/executable_add
Code: int add(int a, int b) { return a + b; }
```

**Result**: `unsat` ✓✓✓

→ **DONE!** Code is semantically equivalent to binary.

---

### Alternative Scenario: Logical Bug Detected

**Iteration 2: D-Helix Verification**

```c
int add(int a, int b) {
    return a * b;  // ❌ BUG: multiplication instead of addition
}
```

**D-Helix Result**:
```json
{
  "result": "sat",
  "counterexample": {
    "arg_0": 2,
    "arg_1": 3
  }
}
```

Meaning: When `a=2, b=3`, binary returns `5` but code returns `6`.

### Iteration 3: Semantic Repair

**LLM receives**:
- Original assembly: `add eax, edx`
- Ghidra code: `return param_1 + param_2;`
- Current code: `return a * b;`
- Counterexample: `a=2, b=3` exposes bug

**LLM fixes**:
```c
int add(int a, int b) {
    return a + b;  // ✓ Fixed: changed * to +
}
```

### Iteration 4: Re-verification

**D-Helix Result**: `unsat` ✓✓✓

→ **DONE!** Semantic bug fixed.

---

## Performance Considerations

### Batching Strategy

| Task | Batch Size | Reason |
|------|------------|--------|
| Compilation | 20 | Lightweight, CPU-bound |
| Ghidra Analysis | 12 | Memory-intensive (~15GB per instance) |
| LLM Summaries | 8 | Hardware constraint (vLLM) |
| D-Helix Verification | Sequential | Complex, but 12 workers at API level |

### Expected Timeline

For 164 HumanEval functions:
- **Original**: ~2-3 hours (compilation + static repair only)
- **V2 with D-Helix**: ~4-6 hours (adds semantic verification)

**Per function** (~1-3 min total):
- Compilation: 5-10s
- Ghidra analysis: 10-20s
- Summary generation: 5-10s
- Initial LLM prompt: 10-15s
- Per repair iteration: 10-20s
- D-Helix verification: 30-60s

---

## Troubleshooting

### D-Helix API Not Reachable

**Error**:
```
⚠ Warning: Cannot reach D-Helix API at http://127.0.0.1:10012
```

**Solution**:
1. Check if API server is running:
   ```bash
   curl http://127.0.0.1:10012/health
   ```

2. If not running, start it:
   ```bash
   cd /root/work/D-helix-fixed/fastapi_server
   source /root/.virtualenvs/angr/bin/activate
   python api_server.py
   ```

3. Verify port forwarding (if using SSH tunnel):
   ```bash
   ssh -L 10012:127.0.0.1:10012 user@server
   ```

### D-Helix Verification Timeout

**Error**:
```
[D-Helix] Timeout after 120s
```

**Solutions**:
- Increase `DHELIX_TIMEOUT` in code (line 62)
- Check D-Helix server logs for bottlenecks
- Verify Z3 solver is responding

### Max Iterations Reached

**Output**:
```json
{
  "final_result": "max_iterations_compilable",
  "dhelix_unsat_achieved": false
}
```

**Meaning**: Code compiles but never achieved `unsat` in 15 iterations.

**Solutions**:
- Increase `MAX_REPAIR_ITERATIONS` (line 64)
- Manually inspect the function (may be too complex)
- Check if counterexamples are being used effectively

---

## Future Enhancements

### 1. Parallel D-Helix Verification

Currently sequential to avoid overwhelming the API. Could parallelize with:
```python
with ThreadPoolExecutor(max_workers=4) as executor:
    futures = [executor.submit(call_dhelix_api, ...) for prog in programs]
```

### 2. Counterexample-Guided Repair

More sophisticated parsing of Z3 counterexamples:
- Extract specific variable values
- Identify which branch caused divergence
- Focus LLM attention on problematic code section

### 3. Incremental Verification

Cache D-Helix results for unchanged code:
```python
if code_hash in verified_cache:
    return cached_result
```

### 4. Multi-Function Verification

Currently only verifies `func0`. Could extend to verify all functions in call graph.

---

## References

- **D-Helix Paper**: [Original research on symbolic execution for decompilation]
- **D-Helix API Docs**: `/D-helix-fixed/fastapi_server/API_DOCUMENTATION.md`
- **MissionDecompile**: Original pipeline for LLM-based decompilation repair
- **Z3 Solver**: https://github.com/Z3Prover/z3

---

## Summary

**batched_humaneval_collector_v2.py** enhances the decompilation pipeline with:

1. ✓ **Static Repair**: Ensures code compiles (same as v1)
2. ✓ **Semantic Verification**: D-Helix checks logical correctness
3. ✓ **Semantic Repair**: LLM fixes bugs using counterexamples
4. ✓ **Iterative Refinement**: Loops until `unsat` or max iterations

**Result**: Higher quality decompiled code that is both **syntactically valid** and **semantically equivalent** to the original binary.
