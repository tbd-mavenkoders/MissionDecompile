# VERITAS Demo

This is a standalone demo that processes a single executable binary through the complete VERITAS decompilation pipeline.

## Pipeline Stages

1. **Ghidra Analysis** - Extract pseudocode and assembly from the binary
2. **Type Constraint Generation** - TypeForge + Typehoon analysis for type inference
3. **Type Signature Analysis** - Gemini 2.5 Pro LLM-based type signature inference
4. **LLM Decompilation** - Generate source code from pseudocode
5. **Static Repair** - Fix compilation errors iteratively
6. **Semantic Verification** - VexHelix symbolic execution equivalence checking
7. **Semantic Repair** - Fix semantic divergences using counterexamples

## Requirements

- Python 3.8+
- Ghidra (configured in VERITAS config.yaml)
- Google Gemini API key
- VexHelix API running (optional, for semantic verification)

### Python Dependencies

```bash
pip install google-generativeai pyyaml requests
# Optional for Typehoon:
pip install angr cxxfilt
```

## Usage

### Basic Usage

```bash
python veritas.py --executable /path/to/binary --gemini_api_key YOUR_API_KEY
```

### Full Options

```bash
python veritas.py \
    --executable /path/to/binary \
    --gemini_provider gemini \
    --gemini_model_name gemini-2.5-pro \
    --gemini_api_key YOUR_API_KEY \
    --language c \
    --function_name func0 \
    --opt O0 \
    --output_dir ./output \
    --vexhelix_url http://127.0.0.1:8001 \
    --num_args 3
```

### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--executable` | Yes | - | Path to the executable binary |
| `--gemini_api_key` | Yes | - | Google API key for Gemini |
| `--gemini_provider` | No | `gemini` | LLM provider |
| `--gemini_model_name` | No | `gemini-2.5-pro` | Gemini model name |
| `--language` | No | `c` | Target language (c or cpp) |
| `--function_name` | No | `func0` | Function to decompile |
| `--opt` | No | `O0` | Optimization level (O0-O3) |
| `--output_dir` | No | `./output` | Output directory |
| `--vexhelix_url` | No | `http://127.0.0.1:8001` | VexHelix API URL |
| `--num_args` | No | `3` | Number of function arguments |

## Output

The demo generates two files in the output directory:

1. `<executable_name>_decompiled.c` (or `.cpp`) - The decompiled source code
2. `<executable_name>_stats.json` - Statistics about the decompilation process

## Example

```bash
# Decompile a simple C function
python veritas.py \
    --executable /path/to/func_123.exe \
    --gemini_api_key AIzaSy... \
    --language c \
    --function_name func0
```

## Directory Structure

```
demo/
├── README.md           # This file
├── veritas.py          # Main demo script
├── typeanalysis.py     # Gemini type analysis module
├── prompt.md           # Prompt documentation
├── output/             # Output directory
│   └── .gitkeep
└── utils/              # Demo utilities
    ├── __init__.py
    ├── typeforge.py    # TypeForge constraint extraction
    └── typehoon.py     # Typehoon constraint extraction
```

## Notes

- If VexHelix is unavailable, the demo will still produce compiled code but without semantic verification
- TypeForge requires Ghidra with the TypeForge.java postscript installed
- Typehoon requires angr (pip install angr)
- The demo reuses components from the main VERITAS pipeline in the parent directory
