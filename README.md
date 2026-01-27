# MissionDecompile V6 - VexHelix Integration

Binary-to-source decompilation with semantic verification using VexHelix.

## Pipeline Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    MissionDecompile V6 Pipeline                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. COMPILATION (Parallel, 20 workers)                              │
│     Original C/C++ code → gcc/g++ → Binary                          │
│                                                                      │
│  2. GHIDRA ANALYSIS (Parallel, 12 workers)                          │
│     Binary → Ghidra → Pseudo-code + ASM + CFG                       │
│                                                                      │
│  3. SUMMARY GENERATION (Parallel, 8 workers)                        │
│     ASM + Ghidra pseudo → LLM → Function summary                    │
│                                                                      │
│  4. CODE GENERATION                                                  │
│     Ghidra pseudo + Summary → LLM → Decompiled code                 │
│                                                                      │
│  5. STATIC REPAIR LOOP (up to 3 iterations)                         │
│     If compile fails: Code + Errors → LLM → Fixed code              │
│                                                                      │
│  6. SEMANTIC VERIFICATION (VexHelix)                                │
│     Original binary + Decompiled code → VexHelix API →              │
│     "equivalent" / "different" with counterexample                   │
│                                                                      │
│  7. SEMANTIC REPAIR LOOP (up to 15 total iterations)                │
│     If different: Code + Counterexample → LLM → Fixed code          │
│     Repeat steps 5-7 until equivalent                               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Requirements

- Python 3.10+
- VexHelix API running at `http://127.0.0.1:8001`
- vLLM server running at `http://127.0.0.1:8000`
- Ghidra 11.0.3+
- gcc/g++ compiler

## Quick Start

```bash
# 1. Start VexHelix server (in separate terminal)
cd ../vexhelix
source venv/bin/activate
uvicorn vexhelix.api.server:app --host 0.0.0.0 --port 8001

# 2. Run V6 collector
cd MissionDecompile
source venv/bin/activate
python evaluator/batched_humaneval_collector_v6.py --limit 20
```

## Configuration

Edit `config.yaml`:

```yaml
llm:
  vllm_provider: vllm
  vllm_model_name: openai/gpt-oss-20b
  vllm_base_url: http://127.0.0.1:8000

# Prompts used in pipeline
prompts:
  system_prompt: ...      # Initial decompilation
  compilation_error: ...  # Static repair
  summary_prompt: ...     # Function summarization
  semantic_repair: ...    # Semantic repair with counterexamples
```

## Batching Configuration

In `evaluator/batched_humaneval_collector_v6.py`:

| Parameter | Value | Description |
|-----------|-------|-------------|
| COMPILATION_BATCH_SIZE | 20 | Concurrent gcc/g++ compilations |
| GHIDRA_BATCH_SIZE | 12 | Concurrent Ghidra analyses |
| LLM_BATCH_SIZE | 8 | Concurrent LLM requests |
| CONCURRENT_REPAIR_SIZE | 16 | Concurrent static repairs |
| VEXHELIX_TIMEOUT | 120s | Per-verification timeout |
| MAX_REPAIR_ITERATIONS | 15 | Max total repair attempts |

## Token Limits (GPT-OSS-20B: 130K context)

| Limit | Value | Purpose |
|-------|-------|---------|
| MAX_ERROR_CHARS | 2000 | Truncate compilation errors |
| MAX_ASM_CHARS | 8000 | Truncate assembly code |
| MAX_CODE_CHARS | 12000 | Truncate source code |

## Dataset

HumanEval-Decompile: 1312 samples (656 C, 656 C++)

Located at: `data/humaneval-decompile/humaneval-decompile.json`

## Output

Results saved to: `output/humaneval-decompile/batched_enriched_humaneval_decompile_v6.json`

## Testing

```bash
# Run pipeline test (10 C + 10 C++ samples)
python tests/v6_integration/test_pipeline_20.py
```

## Time Estimates

| Samples | Estimated Time | Notes |
|---------|----------------|-------|
| 20 | ~3-5 minutes | Test run |
| 100 | ~15-25 minutes | Quick evaluation |
| 656 (C only) | ~1.5-2 hours | Full C dataset |
| 1312 (all) | ~3-4 hours | Full dataset |

Based on ~60s/sample average (including LLM + VexHelix verification).

## VexHelix API

VexHelix uses bounded relational symbolic execution with angr VEX IR.

**Endpoint:** `POST /verify`

**Parameters:**
- `original_binary`: Binary file
- `decompiled_code`: Source code string
- `function_name`: Target function (e.g., "func0")
- `language`: "c" or "cpp"
- `num_args`: Number of arguments (default: 3)
- `loop_bound`: Max loop iterations (default: 5)
- `timeout`: Seconds (default: 120)

**Response:**
```json
{
  "status": "equivalent" | "different" | "timeout" | "error",
  "equivalent": true | false,
  "divergences": [{"type": "return_value_mismatch", "inputs": [...]}],
  "statistics": {"states_orig": N, "states_dec": M}
}
```

## Key Differences from V2 (D-Helix)

| Feature | V2 (D-Helix) | V6 (VexHelix) |
|---------|--------------|---------------|
| Backend | KLEE + Z3 | angr VEX IR |
| C++ Support | Limited | Full |
| Result | SAT/UNSAT | equivalent/different |
| Counterexamples | Z3 model | Concrete inputs |
| Speed | Slower (LLVM IR) | Faster (binary) |
