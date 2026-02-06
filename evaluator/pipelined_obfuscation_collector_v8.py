"""
Pipelined Obfuscation Collector V8 - GEMINI SIGNATURES + ASM VERIFICATION VERSION

This collector processes OBFUSCATED binaries (bogus and cff) through the same
pipeline architecture as pipelined_mbpp_collector_v8.py.

Key Features:
- PRE-COMPUTED GEMINI SIGNATURES (from obfuscation type analysis)
- TYPE CONSTRAINTS from TypeForge/Typehoon
- ASM-BASED VERIFICATION PROTOCOL (4 heuristics for C type validation)
- Static repair (ensure compilation)
- Semantic verification via VexHelix API
- TRUE PIPELINED parallel execution
- Dual LLM endpoints for higher throughput

Dataset:
- Obfuscation dataset: /workspace/home/b220032cs/fyp/repos/ansaf/Obfuscation/veritascator/data/dataset/obfuscated_dataset.json
- Fields for BOGUS: ghidra_bogus, asm_bogus
- Fields for CFF (Control Flow Flattening): ghidra_control, asm_control

Filtering (per user requirements):
- ALL BOGUS cases (164 entries)
- ALL CFF cases (164 entries)
- Only O2 optimization level
- Total: 328 entries

Pipeline Architecture:
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  COMPILE    │──►│   GHIDRA    │──►│  SUMMARIES  │──►│  VEXHELIX   │
│  width=24   │   │  width=24   │   │  width=12   │   │  width=12   │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
     ↑                  ↑                 ↑                  ↑
 compile_q          ghidra_q          summary_q          vexhelix_q
"""

import yaml
from pathlib import Path
import shutil
import tempfile
import os
import sys
import datetime
from typing import Tuple, List, Dict, Optional
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import time
from dataclasses import dataclass, field
import requests
import threading
from queue import Queue
import copy

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.llm_interface import (
    create_llm_interface, 
    LLMInterface, 
    GLOBAL_RATE_LIMITER,
    set_global_rate_limit,
    get_rate_limiter_stats
)
from utils.compile import Compiler, OptimizationLevel
from utils.ghidra import Ghidra
from utils.clean_errors import ErrorNormalizer
from src.sort_callgraph import build_call_graph, topological_sort
from utils.typehoon_poc import extract_typehoon_constraints, format_typehoon_for_prompt

# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

# =============================================================================
# PATHS AND CONFIGURATION
# =============================================================================

# Obfuscation dataset path
OBFUSCATION_DATASET_PATH = Path("/workspace/home/b220032cs/fyp/repos/ansaf/Obfuscation/veritascator/data/dataset/obfuscated_dataset.json")

# Pre-computed Gemini signatures path
GEMINI_SIGNATURES_PATH = Path(__file__).resolve().parent.parent.parent / "references" / "obfuscation_gemini_signatures.json"
BOGUS_SIGNATURES_PATH = Path(__file__).resolve().parent.parent.parent / "references" / "obfuscation_bogus_signatures.json"
CFF_SIGNATURES_PATH = Path(__file__).resolve().parent.parent.parent / "references" / "obfuscation_cff_signatures.json"

# Output directory
OUTPUT_DIR = Path(config.get("obfuscation", {}).get("output_path", 
    str(Path(__file__).resolve().parent.parent / "output" / "obfuscation")))

# =============================================================================
# V8: GEMINI SIGNATURES - PRE-COMPUTED TYPE INFORMATION
# =============================================================================
_gemini_signatures: Dict[str, Dict] = {}
_bogus_signatures: Dict[str, Dict] = {}
_cff_signatures: Dict[str, Dict] = {}

def _load_gemini_signatures():
    """Load pre-computed Gemini signatures for obfuscation."""
    global _gemini_signatures, _bogus_signatures, _cff_signatures
    
    # Load combined signatures
    if GEMINI_SIGNATURES_PATH.exists():
        try:
            with open(GEMINI_SIGNATURES_PATH, 'r') as f:
                _gemini_signatures = json.load(f)
            print(f"[V8] Loaded {len(_gemini_signatures)} combined Gemini signatures")
        except Exception as e:
            print(f"[V8] ERROR loading combined signatures: {e}")
    
    # Load bogus signatures
    if BOGUS_SIGNATURES_PATH.exists():
        try:
            with open(BOGUS_SIGNATURES_PATH, 'r') as f:
                _bogus_signatures = json.load(f)
            print(f"[V8] Loaded {len(_bogus_signatures)} bogus signatures")
        except Exception as e:
            print(f"[V8] ERROR loading bogus signatures: {e}")
    
    # Load CFF signatures
    if CFF_SIGNATURES_PATH.exists():
        try:
            with open(CFF_SIGNATURES_PATH, 'r') as f:
                _cff_signatures = json.load(f)
            print(f"[V8] Loaded {len(_cff_signatures)} CFF signatures")
        except Exception as e:
            print(f"[V8] ERROR loading CFF signatures: {e}")


def get_gemini_signature(index: int, obfuscation_type: str) -> Optional[Dict]:
    """
    Get pre-computed Gemini signature for an obfuscated function.
    
    Args:
        index: The dataset index
        obfuscation_type: 'bogus' or 'cff'
    
    Returns:
        Dict with signature info or None if not found
    """
    # Try type-specific signatures first
    if obfuscation_type == 'bogus':
        # Key format: "{index}_O0" or "{index}_O3"
        # But we need to find by index across all opt levels
        for key, sig in _bogus_signatures.items():
            if sig.get('index') == index:
                return sig
    elif obfuscation_type in ['cff', 'control']:
        for key, sig in _cff_signatures.items():
            if sig.get('index') == index:
                return sig
    
    # Fallback to combined signatures
    for key, sig in _gemini_signatures.items():
        if sig.get('index') == index:
            return sig
    
    return None


def format_gemini_signature_for_prompt(signature: Dict) -> str:
    """
    Format Gemini signature as a string for inclusion in prompts.
    
    Args:
        signature: Signature dictionary from type analysis
    
    Returns:
        Formatted string describing the signature
    """
    if not signature:
        return ""
    
    # Extract signature info from analysed_signature
    analysed = signature.get('analysed_signature', {})
    arg_types = analysed.get('arg_types', [])
    return_type = analysed.get('return_type', 'unknown')
    arg_count = analysed.get('arg_count', len(arg_types))
    
    # Also include original signature for reference
    original = signature.get('original_signature', {})
    orig_arg_types = original.get('arg_types', [])
    orig_return = original.get('return_type', 'unknown')
    
    lines = [
        "═══════════════════════════════════════════════════════════════════════════════",
        "GEMINI-VERIFIED FUNCTION SIGNATURE (MANDATORY - YOU MUST USE THESE EXACT TYPES)",
        "═══════════════════════════════════════════════════════════════════════════════",
        "",
        f"Return Type: {return_type}",
        f"Number of Arguments: {arg_count}",
        "Argument Types:"
    ]
    
    for i, arg_type in enumerate(arg_types):
        lines.append(f"  Argument {i+1}: {arg_type}")
    
    lines.extend([
        "",
        "ORIGINAL GROUND TRUTH SIGNATURE (for reference):",
        f"  Return: {orig_return}, Args: {orig_arg_types}",
        "",
        "⚠️ CRITICAL: These types have been verified by Gemini analysis and are CORRECT.",
        "⚠️ You MUST use these EXACT types in your output code.",
        "⚠️ DO NOT change the return type, argument count, or argument types.",
        "⚠️ If Ghidra/decompiler says different types, IGNORE Ghidra - USE GEMINI TYPES.",
        "═══════════════════════════════════════════════════════════════════════════════"
    ])
    
    return "\n".join(lines)


# Load signatures at module import
_load_gemini_signatures()

# =============================================================================
# Initialize tools
# =============================================================================
c = Compiler()
g = Ghidra()

# DUAL LLM ENDPOINTS for GPT-OSS 120B (batch size 12 each = effective 24)
LLM_ENDPOINTS = [
    "http://192.168.5.13:8000",
    "http://localhost:8000"
]

llm_interface_1 = create_llm_interface(
    provider=config["llm"]["vllm_provider"],
    model_name=config["llm"]["vllm_model_name"],
    base_url=LLM_ENDPOINTS[0]
)

llm_interface_2 = create_llm_interface(
    provider=config["llm"]["vllm_provider"],
    model_name=config["llm"]["vllm_model_name"],
    base_url=LLM_ENDPOINTS[1]
)


class DualLLMDispatcher:
    """Round-robin dispatcher for 2 LLM endpoints, effective batch size 24 (12 per endpoint)."""
    
    def __init__(self, interface1, interface2):
        self._interfaces = [interface1, interface2]
        self._counter = 0
        self._lock = threading.Lock()
    
    def generate(self, prompt, **kwargs):
        """Round-robin dispatch to alternate endpoints."""
        with self._lock:
            idx = self._counter % 2
            self._counter += 1
        return self._interfaces[idx].generate(prompt, **kwargs)
    
    def get_stats(self):
        """Return dispatch statistics."""
        return {"total_dispatched": self._counter}


llm_interface = DualLLMDispatcher(llm_interface_1, llm_interface_2)

# PIPELINED VERSION: Effectively unlimited rate limit for local model
set_global_rate_limit(100000)

# Thread-safe progress tracking
print_lock = threading.Lock()
active_count = 0
completed_count = 0
total_tasks = 0

# =============================================================================
# CONFIGURATION
# =============================================================================

# PIPELINE STAGE WIDTHS
PIPELINE_COMPILE_WIDTH = 24
PIPELINE_GHIDRA_WIDTH = 24
PIPELINE_SUMMARY_WIDTH = 24
PIPELINE_VEXHELIX_WIDTH = 24

# Batch sizes
COMPILATION_BATCH_SIZE = 24
GHIDRA_BATCH_SIZE = 24
LLM_BATCH_SIZE = 24
CONCURRENT_REPAIR_SIZE = 24

# VexHelix API configuration
VEXHELIX_API_URL = "http://127.0.0.1:8001"
VEXHELIX_TIMEOUT = 180
VEXHELIX_LOOP_BOUND = 5
VEXHELIX_RETRIES = 3

# Repair configuration
MAX_REPAIR_ITERATIONS = 5
MAX_STATIC_REPAIR_PER_CYCLE = 3
MAX_STAGNANT_ITERATIONS = 3
PARALLEL_REPAIR_WORKERS = 24
MAX_CODE_HISTORY = 2

# Token limit configuration
MAX_CONTEXT_TOKENS = 130_000
MAX_ERROR_CHARS = 2000
MAX_ASM_CHARS = 8000
MAX_CODE_CHARS = 12000
MAX_TYPE_CONSTRAINT_CHARS = 3000


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class VexHelixResult:
    """Result from VexHelix verification."""
    success: bool
    status: Optional[str]
    equivalent: Optional[bool]
    divergences: Optional[List[Dict]]
    statistics: Optional[Dict]
    error_message: Optional[str]
    compilation_error: Optional[str]


@dataclass
class CompilationResult:
    """Result of compiling a single program."""
    index: int
    success: bool
    executable_path: Optional[Path]
    error_message: Optional[str]
    data: Dict
    obfuscation_type: str


# =============================================================================
# DATASET LOADING AND FILTERING
# =============================================================================

def load_obfuscation_dataset() -> List[Dict]:
    """Load the obfuscation dataset."""
    if not OBFUSCATION_DATASET_PATH.exists():
        print(f"[ERROR] Obfuscation dataset not found: {OBFUSCATION_DATASET_PATH}")
        return []
    
    with open(OBFUSCATION_DATASET_PATH, 'r') as f:
        dataset = json.load(f)
    
    print(f"[Dataset] Loaded {len(dataset)} entries from obfuscation dataset")
    return dataset


def filter_dataset_for_collector(dataset: List[Dict]) -> List[Dict]:
    """
    Filter dataset to:
    - Only O2 optimization level
    - ALL bogus cases
    - ALL cff cases
    
    For each O2 function, we create TWO entries: one for bogus and one for cff.
    Total: 164 bogus + 164 cff = 328 entries
    """
    # Filter to O2 only
    o2_entries = [d for d in dataset if d.get('opt') == 'O2']
    
    print(f"[Filter] O2 entries: {len(o2_entries)}")
    
    # Build filtered entries: for each O2 entry, create entries for both obfuscation types
    filtered_entries = []
    
    for data in o2_entries:
        # Create BOGUS entry
        bogus_entry = {
            'index': data['index'],
            'original_index': data['index'],
            'func_name': data.get('func_name', 'func0'),
            'func': data['func'],
            'func_dep': data['func_dep'],
            'test': data['test'],
            'opt': data['opt'],
            'language': data.get('language', 'c'),
            'obfuscation_type': 'bogus',
            'ghidra_code': data.get('ghidra_bogus', ''),
            'asm': '\n'.join(data.get('asm_bogus', [])) if isinstance(data.get('asm_bogus'), list) else data.get('asm_bogus', ''),
            'original_asm': data.get('asm', ''),
            'original_ghidra': data.get('ghidra_pseudo', ''),
        }
        filtered_entries.append(bogus_entry)
        
        # Create CFF entry
        cff_entry = {
            'index': data['index'],
            'original_index': data['index'],
            'func_name': data.get('func_name', 'func0'),
            'func': data['func'],
            'func_dep': data['func_dep'],
            'test': data['test'],
            'opt': data['opt'],
            'language': data.get('language', 'c'),
            'obfuscation_type': 'cff',
            'ghidra_code': data.get('ghidra_control', ''),
            'asm': '\n'.join(data.get('asm_control', [])) if isinstance(data.get('asm_control'), list) else data.get('asm_control', ''),
            'original_asm': data.get('asm', ''),
            'original_ghidra': data.get('ghidra_pseudo', ''),
        }
        filtered_entries.append(cff_entry)
    
    # Count by type
    bogus_count = sum(1 for e in filtered_entries if e['obfuscation_type'] == 'bogus')
    cff_count = sum(1 for e in filtered_entries if e['obfuscation_type'] == 'cff')
    o2_count = sum(1 for e in filtered_entries if e['opt'] == 'O2')
    
    print(f"[Filter] Final entries: {len(filtered_entries)}")
    print(f"[Filter]   Bogus: {bogus_count}, CFF: {cff_count}")
    print(f"[Filter]   O2: {o2_count}")
    
    return filtered_entries


# =============================================================================
# VEXHELIX API INTEGRATION
# =============================================================================

def check_vexhelix_health() -> bool:
    """Check if VexHelix API is available and healthy."""
    try:
        response = requests.get(f"{VEXHELIX_API_URL}/health", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"[VexHelix] Health check: {data.get('status', 'unknown')}")
            return data.get('status') == 'healthy'
        return False
    except Exception as e:
        print(f"[VexHelix] Health check failed: {e}")
        return False


def call_vexhelix_api(
    binary_path: Path, 
    decompiled_code: str, 
    function_name: str,
    language: str = "c",
    num_args: int = 3,
    loop_bound: int = 5
) -> VexHelixResult:
    """Call VexHelix API to verify semantic equivalence."""
    lang_str = "cpp" if language.lower() == "cpp" else "c"
    last_error = None
    
    for attempt in range(VEXHELIX_RETRIES):
        try:
            with open(binary_path, 'rb') as binary_file:
                files = {
                    'original_binary': (binary_path.name, binary_file, 'application/octet-stream')
                }
                data = {
                    'decompiled_code': decompiled_code,
                    'function_name': function_name,
                    'language': lang_str,
                    'num_args': str(num_args),
                    'loop_bound': str(VEXHELIX_LOOP_BOUND),
                    'timeout': str(VEXHELIX_TIMEOUT)
                }
                
                response = requests.post(
                    f"{VEXHELIX_API_URL}/verify",
                    files=files,
                    data=data,
                    timeout=VEXHELIX_TIMEOUT + 30
                )
            
            if response.status_code == 200:
                result = response.json()
                status = result.get('status', 'error')
                equivalent = result.get('equivalent', None)
                
                if status == 'equivalent':
                    print(f"[VexHelix] ✓✓✓ EQUIVALENT - Semantic match!")
                elif status == 'different':
                    div_count = len(result.get('divergences', []))
                    print(f"[VexHelix] ✗ DIFFERENT - Found {div_count} divergence(s)")
                elif status == 'timeout':
                    print(f"[VexHelix] ⏱ TIMEOUT")
                elif status == 'error':
                    print(f"[VexHelix] ⚠ ERROR - {result.get('message', 'Unknown')}")
                
                return VexHelixResult(
                    success=True,
                    status=status,
                    equivalent=equivalent,
                    divergences=result.get('divergences'),
                    statistics=result.get('statistics'),
                    error_message=result.get('message') if status == 'error' else None,
                    compilation_error=result.get('compilation_error')
                )
            else:
                last_error = f"HTTP {response.status_code}: {response.text[:500]}"
                if response.status_code >= 500:
                    print(f"[VexHelix] Server error (attempt {attempt + 1}), retrying...")
                    time.sleep(2 ** attempt)
                    continue
                return VexHelixResult(
                    success=False, status='error', equivalent=None, divergences=None,
                    statistics=None, error_message=last_error, compilation_error=None
                )
        
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_error = str(e)[:200]
            if attempt < VEXHELIX_RETRIES - 1:
                print(f"[VexHelix] Connection error (attempt {attempt + 1}), retrying...")
                time.sleep(2 ** attempt)
                continue
        except Exception as e:
            return VexHelixResult(
                success=False, status='error', equivalent=None, divergences=None,
                statistics=None, error_message=str(e)[:200], compilation_error=None
            )
    
    return VexHelixResult(
        success=False, status='error', equivalent=None, divergences=None,
        statistics=None, error_message=f"Failed after {VEXHELIX_RETRIES} retries: {last_error}",
        compilation_error=None
    )


# =============================================================================
# ASM-BASED VERIFICATION PROTOCOL
# =============================================================================
ASM_VERIFICATION_PROTOCOL = """
═══════════════════════════════════════════════════════════════════════════════
ASM-BASED VERIFICATION PROTOCOL - FOR C ASM ONLY! (STRICT OVERRIDE RULES)
═══════════════════════════════════════════════════════════════════════════════
You MUST validate Ghidra's output against the ASM instructions. Ghidra frequently misidentifies signedness and constness.
Apply the following 4 heuristics to the ASM. If they contradict Ghidra, THE ASM WINS.

1. SIGNED vs UNSIGNED MISMATCH (The "Jump" Rule)
   Check the conditional jumps and comparisons acting on the argument registers (rdi, rsi, rdx, rcx, r8, r9).
   • SIGNED: If you see `jg`, `jge`, `jl`, `jle`, `cmovg`, `cmovl`, `idiv`, `cvtsi2ss` (int→float) → The type is SIGNED (int, long).
   • UNSIGNED: If you see `ja`, `jae`, `jb`, `jbe`, `div`, `shl`, `shr` (logical shift) → The type is UNSIGNED (uint, size_t).
   • ERROR TRAP: If Ghidra says `uint` but ASM has `cmp` followed by `jle` → OVERRIDE to `int`.

2. CONST vs NON-CONST (The "Write" Rule)
   Check if the memory pointed to by a pointer argument is ever written to.
   • NON-CONST: If you see `mov [reg], val` or `mov [reg + off], val` using the argument's register.
   • NON-CONST: If the pointer is passed as the *first* argument (destination) to `memset`, `strcpy`, or `memcpy`.
   • CONST: If the pointer is ONLY used in `mov reg, [arg]` (reads) or passed as the *second* argument (source) to copy functions.
   • RULE: If no writes are detected, default to `const Type*` (e.g., `const char*`).

3. ARRAY vs POINTER (The "Addressing" Rule)
   Distinguish `Type*` from `Type[]` based on how memory is accessed.
   • ARRAY (`Type[]`): Look for SIB (Scale-Index-Base) addressing: `(%rdi,%rax,4)` or `[rdi + rax*4]`. This implies index-based access.
   • POINTER (`Type*`): Look for pointer walking: `add $4, %rdi` followed by `mov ... (%rdi)`. This implies iterator/cursor logic.
   • HEURISTIC: If the loop uses an index counter to access memory → `Type[]`. If it increments the pointer itself → `Type*`.

4. VOID vs VALUE (The "Dead Register" Rule)
   Decompilers often say `void` when a function returns a status code (int) or boolean.
   • CHECK: Look at the last 5 instructions before `ret` (or `rep ret`).
   • NOT VOID: If `eax`, `rax`, or `xmm0` are written to (e.g., `xor eax, eax`, `mov eax, 1`, `setz al`) and NOT subsequently clobbered/ignored.
   • BOOLEAN: If the return values are strictly 0 and 1, and the function name implies a check (is/has/valid), prefer `bool` over `int`.
   • ERROR TRAP: `xor eax, eax` followed by `ret` is `return 0;`, NOT `void`!

NOTE: This code was OBFUSCATED before decompilation. The control flow may look unusual due to:
- Bogus obfuscation: Added fake branches and dead code
- CFF (Control Flow Flattening): Loop-based dispatch structure

Focus on the DATA FLOW and COMPUTATIONS, not the unusual control flow structure.
"""


# =============================================================================
# PROMPT GENERATION
# =============================================================================

def get_initial_prompt(
    c_code: str, 
    function_summary: str, 
    type_constraints: Dict,
    language: str, 
    asm: str = "",
    signature_analysis: str = "",
    obfuscation_type: str = ""
) -> str:
    """Generate the initial prompt for decompilation."""
    initial_prompt = config["prompts"]["system_prompt"]
    
    truncated_asm = asm[:5000] if asm else ""
    if asm and len(asm) > 5000:
        truncated_asm += "\n; ... (truncated)"
    
    obf_warning = ""
    if obfuscation_type == 'bogus':
        obf_warning = """
═══════════════════════════════════════════════════════════════════════════════
⚠️ OBFUSCATION WARNING: BOGUS CODE INSERTION
═══════════════════════════════════════════════════════════════════════════════
This binary was obfuscated using BOGUS code insertion. The decompiler output may contain:
- Fake conditional branches that never execute
- Dead code blocks
- Artificial variable assignments
- Spurious function calls

Focus on the ACTUAL computation path. Ignore code that doesn't contribute to the final result.
"""
    elif obfuscation_type == 'cff':
        obf_warning = """
═══════════════════════════════════════════════════════════════════════════════
⚠️ OBFUSCATION WARNING: CONTROL FLOW FLATTENING (CFF)
═══════════════════════════════════════════════════════════════════════════════
This binary was obfuscated using Control Flow Flattening. The decompiler output may show:
- A large switch statement or dispatcher loop
- State variable driving program execution
- Basic blocks as switch cases

The ACTUAL logic is hidden in the dispatch structure. Reconstruct the original control flow from the state transitions.
"""
    
    prompt = f"""{initial_prompt}

{obf_warning}

═══════════════════════════════════════════════════════════════════════════════
IMPORTANT: Decompiler pseudocode is approximate - it may have reconstruction errors!
═══════════════════════════════════════════════════════════════════════════════

The COMPILER OUTPUT below shows the TRUE behavior. Decompiler output may be wrong in:

Common decompiler reconstruction errors:
• Wrong return type: void instead of int/float/double
• Missing float ops: floating-point operations ignored
• Empty loop bodies: operations inside loops omitted
• Wrong param types: int instead of float*, long instead of size_t
• Wrong param count: parameters missing or extra
• Control flow errors: structured loops/ifs incorrectly recovered

═══════════════════════════════════════════════════════════════════════════════
COMPILER OUTPUT (GROUND TRUTH):
═══════════════════════════════════════════════════════════════════════════════
```
{truncated_asm}
```

═══════════════════════════════════════════════════════════════════════════════
DECOMPILER PSEUDOCODE (MAY BE INCORRECT - use as rough guide only):
═══════════════════════════════════════════════════════════════════════════════
```{language}
{c_code}
```

Function Summary: {function_summary}
"""
    
    # Add Gemini signature if available
    if signature_analysis:
        prompt += f"\n{signature_analysis}\n"
    
    # Add ASM verification protocol for C
    if language.lower() == 'c':
        prompt += f"\n{ASM_VERIFICATION_PROTOCOL}\n"
    
    return prompt


def get_static_repair_prompt(
    c_code: str, 
    compilation_errors: str, 
    function_summary: str,
    type_constraints: Dict,
    language: str,
    asm: str = "",
    signature_analysis: str = "",
    obfuscation_type: str = ""
) -> str:
    """Generate the static repair prompt for compilation errors."""
    repair_prompt = config["prompts"]["compilation_error"]
    lang_label = "cpp" if language == "cpp" else "c"
    
    truncated_errors = compilation_errors[:MAX_ERROR_CHARS]
    if len(compilation_errors) > MAX_ERROR_CHARS:
        truncated_errors += "\n... (error truncated)"
    truncated_code = c_code[:MAX_CODE_CHARS]
    if len(c_code) > MAX_CODE_CHARS:
        truncated_code += "\n// ... (code truncated)"
    
    truncated_asm = asm[:MAX_ASM_CHARS] if asm else ""
    if asm and len(asm) > MAX_ASM_CHARS:
        truncated_asm += "\n; ... (truncated)"
    
    prompt = f"{repair_prompt}\n\n```{lang_label}\nLanguage:{language}\nSummary:{function_summary}\nCode:{truncated_code}\n```\n\nCompilation Errors:\n{truncated_errors}\n\nPlease provide the corrected {language.upper()} code."
    
    if signature_analysis:
        prompt += f"\n\n{signature_analysis}\n\n⚠️ CRITICAL: When fixing compilation errors, YOU MUST PRESERVE the Gemini signature types above!"
    
    if truncated_asm:
        prompt += f"\n\nCOMPILER OUTPUT (ground truth):\n```\n{truncated_asm}\n```"
    
    if language.lower() == 'c':
        prompt += f"\n{ASM_VERIFICATION_PROTOCOL}"
    
    return prompt


def get_semantic_repair_prompt(
    original_asm: str,
    original_ghidra: str,
    current_code: str,
    function_summary: str,
    vexhelix_result: VexHelixResult,
    type_constraints: Dict,
    language: str,
    code_history: List[Tuple[str, int]] = None,
    signature_analysis: str = "",
    obfuscation_type: str = ""
) -> str:
    """Generate semantic repair prompt."""
    truncated_asm = original_asm[:MAX_ASM_CHARS] if original_asm else ""
    if original_asm and len(original_asm) > MAX_ASM_CHARS:
        truncated_asm += "\n; ... (assembly truncated)"
    
    truncated_ghidra = original_ghidra[:MAX_CODE_CHARS] if original_ghidra else ""
    if original_ghidra and len(original_ghidra) > MAX_CODE_CHARS:
        truncated_ghidra += "\n// ... (code truncated)"
    
    truncated_current = current_code[:MAX_CODE_CHARS] if current_code else ""
    if current_code and len(current_code) > MAX_CODE_CHARS:
        truncated_current += "\n// ... (current code truncated)"
    
    obf_note = ""
    if obfuscation_type == 'bogus':
        obf_note = "\nNOTE: This was BOGUS obfuscated code - ignore dead code paths."
    elif obfuscation_type == 'cff':
        obf_note = "\nNOTE: This was CFF obfuscated code - reconstruct from state machine structure."
    
    prompt = f"""You are fixing reconstructed code that produces WRONG outputs. The semantic verifier found behavioral differences.

═══════════════════════════════════════════════════════════════════════════════
IMPORTANT: COMPILER OUTPUT IS GROUND TRUTH - Decompiler pseudocode is NOT reliable!
═══════════════════════════════════════════════════════════════════════════════
{obf_note}

═══════════════════════════════════════════════════════════════════════════════
COMPILER OUTPUT (GROUND TRUTH):
═══════════════════════════════════════════════════════════════════════════════
```
{truncated_asm}
```

═══════════════════════════════════════════════════════════════════════════════
DECOMPILER PSEUDOCODE (UNRELIABLE):
═══════════════════════════════════════════════════════════════════════════════
```{language}
{truncated_ghidra}
```

═══════════════════════════════════════════════════════════════════════════════
YOUR CURRENT CODE (WRONG):
═══════════════════════════════════════════════════════════════════════════════
```{language}
{truncated_current}
```

Function Summary: {function_summary}

VERIFICATION: DIFFERENT (your code doesn't match expected behavior)
"""
    
    # Add history of previous attempts
    if code_history and len(code_history) > 0:
        prompt += "\n═══════════════════════════════════════════════════════════════════════════════\n"
        prompt += "PREVIOUS FAILED ATTEMPTS (DO NOT REPEAT THESE MISTAKES):\n"
        prompt += "═══════════════════════════════════════════════════════════════════════════════\n"
        for i, (prev_code, prev_div) in enumerate(code_history[-MAX_CODE_HISTORY:]):
            prev_truncated = prev_code[:3000] if prev_code else ""
            if prev_code and len(prev_code) > 3000:
                prev_truncated += "\n// ... (truncated)"
            prompt += f"\nAttempt {i+1} ({prev_div} divergences) - ALREADY TRIED, FAILED:\n"
            prompt += f"```{language}\n{prev_truncated}\n```\n"
        prompt += "\n⚠️ DO NOT recreate any of the above attempts. Try a DIFFERENT approach.\n"
    
    if signature_analysis:
        prompt += f"\n{signature_analysis}\n\n⚠️ CRITICAL: You MUST use the Gemini-verified types!\n"
    
    if language.lower() == 'c':
        prompt += f"\n{ASM_VERIFICATION_PROTOCOL}\n"
    
    # Format divergences
    if vexhelix_result.divergences:
        prompt += "\n═══════════════════════════════════════════════════════════════════════════════\n"
        prompt += "COUNTEREXAMPLES (inputs where your code gives WRONG answer):\n"
        prompt += "═══════════════════════════════════════════════════════════════════════════════\n"
        for i, div in enumerate(vexhelix_result.divergences[:5]):
            prompt += f"\nTest case {i+1}:\n"
            if div.get('inputs'):
                prompt += "  Inputs: "
                inputs_str = ", ".join([f"{inp.get('name', 'arg')}={inp.get('value', '?')}" for inp in div['inputs']])
                prompt += inputs_str + "\n"
            if div.get('orig_output'):
                orig = div['orig_output']
                prompt += f"  ✓ Expected (from binary): {orig.get('value', '?')}"
                if orig.get('hex'):
                    prompt += f" (0x{orig.get('hex', '?')})"
                prompt += "\n"
            if div.get('dec_output'):
                dec = div['dec_output']
                prompt += f"  ✗ Your output: {dec.get('value', '?')}"
                if dec.get('hex'):
                    prompt += f" (0x{dec.get('hex', '?')})"
                prompt += "\n"
    
    prompt += """
═══════════════════════════════════════════════════════════════════════════════
YOUR TASK: Fix the code to match expected behavior
═══════════════════════════════════════════════════════════════════════════════

Output ONLY the corrected function code. No explanations."""
    
    return prompt


# =============================================================================
# COMPILATION UTILITIES
# =============================================================================

def get_optimization_level(opt_str: str) -> OptimizationLevel:
    """Convert optimization level string to OptimizationLevel enum."""
    opt_map = {
        "O0": OptimizationLevel.O0,
        "O1": OptimizationLevel.O1,
        "O2": OptimizationLevel.O2,
        "O3": OptimizationLevel.O3,
        "-O0": OptimizationLevel.O0,
        "-O1": OptimizationLevel.O1,
        "-O2": OptimizationLevel.O2,
        "-O3": OptimizationLevel.O3,
    }
    return opt_map.get(opt_str, OptimizationLevel.O0)


def compile_code(c_code: str, language: str, temp_dir: Path, opt: str = "O0") -> Tuple[bool, str, Optional[Path]]:
    """Compile code and return (success, message, executable_path)."""
    file_extension = "cpp" if language == "cpp" else "c"
    source_file = temp_dir / f"code.{file_extension}"
    executable_path = temp_dir / "executable.out"
    
    with open(source_file, "w") as f:
        f.write(c_code)
    
    opt_level = get_optimization_level(opt)
    status, message = c.compile_source(
        source_file_path=source_file,
        output_file_path=executable_path,
        opt=opt_level,
        is_cpp=(language == "cpp"),
        c_flag=True
    )
    
    if status:
        return True, message, executable_path
    else:
        return False, message, None


def compile_single_program(data: Dict, temp_base_dir: Path) -> CompilationResult:
    """Compile a single program (original code) and return the result."""
    try:
        c_program = data['func_dep'] + data['func']
        obf_type = data.get('obfuscation_type', 'unknown')
        idx = data['index']
        
        # Use unique directory for each (index, obf_type) combination
        temp_dir = temp_base_dir / f"prog_{idx}_{obf_type}"
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        c_file_path = temp_dir / f"temp.{'cpp' if data['language']=='cpp' else 'c'}"
        executable_path = temp_dir / f"temp_executable_{idx}_{obf_type}"
        
        with open(c_file_path, "w") as f:
            f.write(c_program)
        
        opt_level = get_optimization_level(data.get('opt', 'O0'))
        status, message = c.compile_source(
            source_file_path=str(c_file_path),
            output_file_path=str(executable_path),
            opt=opt_level,
            is_cpp=(data['language'] == "cpp"),
            c_flag=True
        )
        
        if not status:
            print(f"[Compile] Failed for index {idx} ({obf_type}): {message[:100]}")
            return CompilationResult(
                index=idx, success=False, executable_path=None,
                error_message=message, data=data, obfuscation_type=obf_type
            )
        
        return CompilationResult(
            index=idx, success=True, executable_path=executable_path,
            error_message=None, data=data, obfuscation_type=obf_type
        )
    
    except Exception as e:
        print(f"[Compile] Exception for index {data.get('index', '?')}: {e}")
        return CompilationResult(
            index=data.get('index', -1), success=False, executable_path=None,
            error_message=str(e), data=data, obfuscation_type=data.get('obfuscation_type', 'unknown')
        )


# =============================================================================
# MAIN OPTIMIZATION LOOP WITH VEXHELIX
# =============================================================================

def get_optimized_code_v7(
    c_code: str,
    function_summary: str,
    type_constraints: Dict,
    language: str,
    llm_interface,
    original_binary_path: Path,
    function_name: str,
    original_asm: str,
    original_ghidra: str,
    opt: str = "O0",
    num_args: int = 3,
    task_id: str = "",
    signature_analysis: str = "",
    obfuscation_type: str = ""
) -> Tuple[bool, str, str, Dict]:
    """
    Enhanced optimization with VexHelix semantic verification.
    
    Returns:
        (success, v8_optimized_code, v4_5_checkpoint_code, stats)
    """
    prefix = f"[{task_id}]" if task_id else "[Optimize]"
    
    stats = {
        'static_repair_iterations': 0,
        'semantic_repair_iterations': 0,
        'vexhelix_calls': 0,
        'vexhelix_equivalent_achieved': False,
        'final_result': None,
        'language': language,
        'obfuscation_type': obfuscation_type,
        'divergence_history': [],
        'has_type_constraints': bool(type_constraints)
    }
    
    v4_5_checkpoint_code = None
    v4_5_checkpoint_saved = False
    
    best_divergence_count = float('inf')
    stagnant_count = 0
    
    code_history = []
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        print(f"{prefix} Starting optimization ({obfuscation_type})...", flush=True)
        
        initial_prompt = get_initial_prompt(
            c_code=c_code,
            function_summary=function_summary,
            type_constraints=type_constraints,
            language=language,
            asm=original_asm,
            signature_analysis=signature_analysis,
            obfuscation_type=obfuscation_type
        )
        
        try:
            optimized_code = llm_interface.generate(initial_prompt)
            if not optimized_code.strip():
                raise RuntimeError("LLM returned empty response")
        except Exception as e:
            print(f"{prefix} ERROR: Initial LLM generation failed: {e}")
            stats['final_result'] = 'llm_error'
            return False, c_code, None, stats
        
        for iteration in range(MAX_REPAIR_ITERATIONS):
            print(f"{prefix} === Iteration {iteration + 1}/{MAX_REPAIR_ITERATIONS} ===")
            
            # Phase 1: Static Repair
            compile_success, compile_message, executable_path = compile_code(
                optimized_code, language, temp_path, opt
            )
            
            if not compile_success:
                print(f"{prefix} [Static] Code doesn't compile, fixing...")
                stats['static_repair_iterations'] += 1
                
                e = ErrorNormalizer()
                error_prompt = e.format_for_llm(compile_message)
                
                repair_prompt = get_static_repair_prompt(
                    c_code=optimized_code,
                    compilation_errors=error_prompt,
                    function_summary=function_summary,
                    type_constraints=type_constraints,
                    language=language,
                    asm=original_asm,
                    signature_analysis=signature_analysis,
                    obfuscation_type=obfuscation_type
                )
                
                try:
                    new_code = llm_interface.generate(repair_prompt)
                    if new_code.strip():
                        optimized_code = new_code
                except Exception as ex:
                    print(f"{prefix} [Static] LLM error: {ex}")
                continue
            
            print(f"{prefix} [Static] ✓ Compiles")
            
            # V4.5 checkpoint
            if not v4_5_checkpoint_saved:
                v4_5_checkpoint_code = optimized_code
                v4_5_checkpoint_saved = True
                print(f"{prefix} [V4.5] ★ Checkpoint saved")
            
            # Phase 2: Semantic Verification
            print(f"{prefix} [Semantic] Calling VexHelix...")
            stats['vexhelix_calls'] += 1
            
            vexhelix_result = call_vexhelix_api(
                binary_path=original_binary_path,
                decompiled_code=optimized_code,
                function_name=function_name,
                language=language,
                num_args=num_args,
                loop_bound=5
            )
            
            if not vexhelix_result.success and vexhelix_result.status == 'error':
                if vexhelix_result.compilation_error:
                    print(f"{prefix} [Semantic] VexHelix compile error, fixing...")
                    stats['static_repair_iterations'] += 1
                    
                    repair_prompt = get_static_repair_prompt(
                        c_code=optimized_code,
                        compilation_errors=vexhelix_result.compilation_error,
                        function_summary=function_summary,
                        type_constraints=type_constraints,
                        language=language,
                        asm=original_asm,
                        signature_analysis=signature_analysis,
                        obfuscation_type=obfuscation_type
                    )
                    try:
                        new_code = llm_interface.generate(repair_prompt)
                        if new_code.strip():
                            optimized_code = new_code
                    except Exception as ex:
                        print(f"{prefix} [Semantic] LLM error: {ex}")
                    continue
                
                print(f"{prefix} [Semantic] VexHelix API error: {vexhelix_result.error_message}")
                stats['final_result'] = 'vexhelix_error'
                return True, optimized_code, v4_5_checkpoint_code, stats
            
            if vexhelix_result.status == 'timeout':
                print(f"{prefix} [Semantic] VexHelix timeout")
                stats['final_result'] = 'vexhelix_timeout'
                return True, optimized_code, v4_5_checkpoint_code, stats
            
            if vexhelix_result.status == 'equivalent' or vexhelix_result.equivalent:
                print(f"{prefix} ✓✓✓ EQUIVALENT!")
                stats['vexhelix_equivalent_achieved'] = True
                stats['final_result'] = 'equivalent'
                return True, optimized_code, v4_5_checkpoint_code, stats
            
            # Semantic repair needed
            divergence_count = len(vexhelix_result.divergences) if vexhelix_result.divergences else 1000
            stats['divergence_history'].append(divergence_count)
            
            # Track history
            code_history.append((optimized_code, divergence_count))
            
            # Check stagnation
            if divergence_count >= best_divergence_count:
                stagnant_count += 1
                if stagnant_count >= MAX_STAGNANT_ITERATIONS:
                    print(f"{prefix} [Semantic] Stagnated, stopping")
                    stats['final_result'] = 'stagnated'
                    return True, optimized_code, v4_5_checkpoint_code, stats
            else:
                best_divergence_count = divergence_count
                stagnant_count = 0
            
            # Semantic repair
            print(f"{prefix} [Semantic] {divergence_count} divergences, repairing...")
            stats['semantic_repair_iterations'] += 1
            
            repair_prompt = get_semantic_repair_prompt(
                original_asm=original_asm,
                original_ghidra=original_ghidra,
                current_code=optimized_code,
                function_summary=function_summary,
                vexhelix_result=vexhelix_result,
                type_constraints=type_constraints,
                language=language,
                code_history=code_history,
                signature_analysis=signature_analysis,
                obfuscation_type=obfuscation_type
            )
            
            try:
                new_code = llm_interface.generate(repair_prompt)
                if new_code.strip():
                    optimized_code = new_code
            except Exception as ex:
                print(f"{prefix} [Semantic] LLM error: {ex}")
        
        stats['final_result'] = 'max_iterations'
        return True, optimized_code, v4_5_checkpoint_code, stats


# =============================================================================
# PIPELINE STAGES
# =============================================================================

PIPELINE_DONE = object()


def _pipeline_compile_stage(
    input_q: Queue, 
    output_q: Queue, 
    temp_base_dir: Path,
    dropped_counter: Dict,
    counter_lock: threading.Lock,
    stage_id: str = "COMPILE"
):
    """Pipeline Stage 1: Compile programs."""
    def worker():
        while True:
            item = input_q.get()
            if item is PIPELINE_DONE:
                input_q.task_done()
                break
            
            try:
                data = item
                idx = data['index']
                obf_type = data.get('obfuscation_type', '?')
                lang = data.get('language', 'c')
                
                with print_lock:
                    print(f"[{stage_id}] P{idx} ({obf_type}) compiling...", flush=True)
                
                result = compile_single_program(data, temp_base_dir)
                
                if result.success:
                    with print_lock:
                        print(f"[{stage_id}] P{idx} ({obf_type}) ✓", flush=True)
                    output_q.put({
                        'data': data,
                        'compile_result': result
                    })
                else:
                    with counter_lock:
                        dropped_counter['compile'] += 1
                    with print_lock:
                        print(f"[{stage_id}] P{idx} ({obf_type}) ✗ compile failed", flush=True)
            except Exception as e:
                with counter_lock:
                    dropped_counter['compile'] += 1
                with print_lock:
                    print(f"[{stage_id}] P{item.get('index', '?')} exception: {e}", flush=True)
            finally:
                input_q.task_done()
    
    return worker


def _pipeline_ghidra_stage(
    input_q: Queue, 
    output_q: Queue, 
    dropped_counter: Dict,
    counter_lock: threading.Lock,
    stage_id: str = "GHIDRA"
):
    """Pipeline Stage 2: Ghidra analysis."""
    cfg_script = Path(__file__).resolve().parent.parent / "src" / "scripts" / "batched_cfg_extractor.py"
    callgraph_script = Path(__file__).resolve().parent.parent / "src" / "scripts" / "batched_call_graph_extractor.py"
    
    def analyze_single(idx: int, exe_path: Path, obf_type: str) -> Dict:
        """Analyze a single executable."""
        executable_name = exe_path.stem
        output_dir_path = OUTPUT_DIR / "SOG" / f"{executable_name}_{obf_type}"
        if output_dir_path.exists():
            shutil.rmtree(output_dir_path)
        output_dir_path.mkdir(parents=True, exist_ok=True)
        
        cfg_map = g.extract_cfg(exe_path, output_dir_path)
        callgraph_map = g.extract_call_graph(exe_path, output_dir_path)
        
        return {
            'cfg_map': cfg_map,
            'callgraph_map': callgraph_map,
            'output_dir': output_dir_path,
            'executable_name': executable_name
        }
    
    def worker():
        while True:
            item = input_q.get()
            if item is PIPELINE_DONE:
                input_q.task_done()
                break
            
            try:
                data = item['data']
                compile_result = item['compile_result']
                idx = data['index']
                obf_type = data.get('obfuscation_type', '?')
                lang = data.get('language', 'c')
                
                with print_lock:
                    print(f"[{stage_id}] P{idx} ({obf_type}) analyzing...", flush=True)
                
                ghidra_result = analyze_single(idx, compile_result.executable_path, obf_type)
                
                if ghidra_result is not None:
                    with print_lock:
                        print(f"[{stage_id}] P{idx} ({obf_type}) ✓", flush=True)
                    output_q.put({
                        'data': data,
                        'compile_result': compile_result,
                        'ghidra_result': ghidra_result
                    })
                else:
                    with counter_lock:
                        dropped_counter['ghidra'] += 1
                    with print_lock:
                        print(f"[{stage_id}] P{idx} ({obf_type}) ✗ ghidra failed", flush=True)
            except Exception as e:
                with counter_lock:
                    dropped_counter['ghidra'] += 1
                with print_lock:
                    print(f"[{stage_id}] P{item['data'].get('index', '?')} exception: {e}", flush=True)
            finally:
                input_q.task_done()
    
    return worker


def _pipeline_summary_stage(
    input_q: Queue, 
    output_q: Queue, 
    dropped_counter: Dict,
    counter_lock: threading.Lock,
    stage_id: str = "SUMMARY"
):
    """Pipeline Stage 3: LLM summary generation with Gemini signatures."""
    def worker():
        while True:
            item = input_q.get()
            if item is PIPELINE_DONE:
                input_q.task_done()
                break
            
            try:
                data = item['data']
                compile_result = item['compile_result']
                ghidra_result = item['ghidra_result']
                idx = data['index']
                obf_type = data.get('obfuscation_type', '?')
                lang = data.get('language', 'c')
                
                with print_lock:
                    print(f"[{stage_id}] P{idx} ({obf_type}) generating...", flush=True)
                
                # Build enriched data
                enriched_data = {
                    'index': idx,
                    'original_index': data.get('original_index', idx),
                    'language': lang,
                    'obfuscation_type': obf_type,
                    'opt': data.get('opt', 'O0'),
                    'original_binary_path': str(compile_result.executable_path),
                    'callgraph': ghidra_result.get('callgraph_map', {}),
                    'func': data.get('func', ''),
                    'func_dep': data.get('func_dep', ''),
                    'test': data.get('test', ''),
                    'functions': []
                }
                
                # Create function data
                func_data = {
                    'f_name': data.get('func_name', 'func0'),
                    'ghidra_code': data.get('ghidra_code', ''),
                    'asm': data.get('asm', ''),
                    'original_asm': data.get('original_asm', ''),
                    'original_ghidra': data.get('original_ghidra', ''),
                    'type_constraints': {},
                    'gemini_signature': None,
                    'signature_analysis': ''
                }
                
                # Get Gemini signature
                gemini_sig = get_gemini_signature(idx, obf_type)
                if gemini_sig:
                    func_data['gemini_signature'] = gemini_sig
                    func_data['signature_analysis'] = format_gemini_signature_for_prompt(gemini_sig)
                    with print_lock:
                        analysed = gemini_sig.get('analysed_signature', {})
                        print(f"[{stage_id}] P{idx} Gemini signature: ret={analysed.get('return_type')}, args={analysed.get('arg_count')}", flush=True)
                else:
                    with print_lock:
                        print(f"[{stage_id}] P{idx} WARNING: No Gemini signature!", flush=True)
                
                # Generate summary
                summary_prompt = config["prompts"]["summary_prompt"]
                prompt = f"{summary_prompt}"
                
                if func_data.get('signature_analysis'):
                    prompt += f"\n\n{func_data['signature_analysis']}"
                
                if func_data.get('ghidra_code'):
                    prompt += f"\n\nGhidra Decompiled Code (MAY BE WRONG - USE GEMINI SIGNATURE!):\n```c\n{func_data['ghidra_code']}\n```"
                
                if func_data.get('asm'):
                    prompt += f"\n\nAssembly Instructions:\n```asm\n{func_data['asm'][:2500]}\n```"
                
                func_data['function_summary'] = llm_interface.generate(prompt)
                
                enriched_data['functions'].append(func_data)
                
                has_gemini = func_data.get('gemini_signature') is not None
                status_str = f"{'G' if has_gemini else '-'}"
                
                with print_lock:
                    print(f"[{stage_id}] P{idx} ({obf_type}) [{status_str}] ✓", flush=True)
                
                output_q.put({
                    'enriched_data': enriched_data,
                    'lang': lang,
                    'idx': idx,
                    'obf_type': obf_type
                })
            except Exception as e:
                with counter_lock:
                    dropped_counter['summary'] += 1
                with print_lock:
                    print(f"[{stage_id}] P{item['data'].get('index', '?')} exception: {e}", flush=True)
            finally:
                input_q.task_done()
    
    return worker


def _pipeline_vexhelix_stage(
    input_q: Queue, 
    results: List,
    results_lock: threading.Lock,
    counters: Dict,
    total_tasks: int,
    incremental_save_dir: Path,
    stage_id: str = "VEXHELIX"
):
    """Pipeline Stage 4: VexHelix semantic repair loop."""
    v4_5_save_dir = incremental_save_dir / "v4_5"
    v8_save_dir = incremental_save_dir / "v8"
    v4_5_save_dir.mkdir(parents=True, exist_ok=True)
    v8_save_dir.mkdir(parents=True, exist_ok=True)
    
    def worker():
        while True:
            item = input_q.get()
            if item is PIPELINE_DONE:
                input_q.task_done()
                break
            
            try:
                enriched_data = item['enriched_data']
                lang = item['lang']
                idx = item['idx']
                obf_type = item.get('obf_type', '?')
                task_id = f"P{idx}_{obf_type}"
                
                has_gemini = any(f.get('gemini_signature') for f in enriched_data['functions'])
                status_str = "G" if has_gemini else "-"
                
                with print_lock:
                    counters['active'] += 1
                    print(f"[{stage_id}] {task_id} [{status_str}] START | active: {counters['active']}", flush=True)
                
                start_time = time.time()
                
                for func_data in enriched_data['functions']:
                    opt_level = enriched_data.get('opt', 'O0')
                    sig_analysis = func_data.get('signature_analysis', '')
                    
                    optimization_success, optimized_code, v4_5_checkpoint_code, stats = get_optimized_code_v7(
                        c_code=func_data['ghidra_code'],
                        function_summary=func_data['function_summary'],
                        type_constraints=func_data.get('type_constraints', {}),
                        language=lang,
                        llm_interface=llm_interface,
                        original_binary_path=Path(enriched_data['original_binary_path']),
                        function_name=func_data['f_name'],
                        original_asm=func_data.get('asm', ''),
                        original_ghidra=func_data.get('original_ghidra', ''),
                        opt=opt_level,
                        num_args=3,
                        task_id=task_id,
                        signature_analysis=sig_analysis,
                        obfuscation_type=obf_type
                    )
                    
                    func_data['optimization_status'] = optimization_success
                    func_data['optimized_code'] = optimized_code
                    func_data['v4_5_checkpoint_code'] = v4_5_checkpoint_code
                    func_data['optimization_stats'] = stats
                
                duration = time.time() - start_time
                final_result = enriched_data['functions'][0].get('optimization_stats', {}).get('final_result', 'unknown') if enriched_data['functions'] else 'no_functions'
                
                with results_lock:
                    results.append(enriched_data)
                
                # Save incrementally
                try:
                    # V8 result
                    v8_file = v8_save_dir / f"func_{idx}_{obf_type}.json"
                    with open(v8_file, 'w') as f:
                        json.dump(enriched_data, f, indent=2)
                    
                    # V4.5 result
                    v4_5_enriched_data = copy.deepcopy(enriched_data)
                    for fd in v4_5_enriched_data['functions']:
                        v4_5_code = fd.get('v4_5_checkpoint_code')
                        if v4_5_code:
                            fd['optimized_code'] = v4_5_code
                        if 'optimization_stats' in fd:
                            fd['optimization_stats']['version'] = 'v4.5'
                            fd['optimization_stats']['final_result'] = 'static_repair_only'
                    
                    v4_5_file = v4_5_save_dir / f"func_{idx}_{obf_type}.json"
                    with open(v4_5_file, 'w') as f:
                        json.dump(v4_5_enriched_data, f, indent=2)
                        
                except Exception as save_err:
                    print(f"[SAVE] Warning: Failed to save for {task_id}: {save_err}")
                
                with print_lock:
                    counters['active'] -= 1
                    counters['completed'] += 1
                    sym = "✓" if final_result == 'equivalent' else "✗"
                    stats = enriched_data['functions'][0].get('optimization_stats', {}) if enriched_data['functions'] else {}
                    print(f"[{sym}] {task_id} [{status_str}]: {final_result} "
                          f"({stats.get('semantic_repair_iterations', 0)}it, "
                          f"{stats.get('vexhelix_calls', 0)}vex, {duration:.1f}s) | "
                          f"done: {counters['completed']}/{total_tasks}", flush=True)
                
            except Exception as e:
                with print_lock:
                    counters['active'] -= 1
                    counters['completed'] += 1
                    print(f"[✗] P{item.get('idx', '?')} exception: {str(e)[:100]} | "
                          f"done: {counters['completed']}/{total_tasks}", flush=True)
            finally:
                input_q.task_done()
    
    return worker


# =============================================================================
# MAIN PIPELINE PROCESSING
# =============================================================================

def process_batch_pipelined(batch_items: List[Dict], temp_base_dir: Path, incremental_save_dir: Path = None) -> Tuple[List[Dict], Path]:
    """Process a batch using TRUE PIPELINED ARCHITECTURE."""
    total = len(batch_items)
    
    if incremental_save_dir is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        incremental_save_dir = OUTPUT_DIR / f"run_{timestamp}"
    incremental_save_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'='*70}")
    print(f"[PIPELINED V8] Obfuscation Collector with Gemini + VexHelix")
    print(f"{'='*70}")
    print(f"  Total programs: {total}")
    print(f"  Stage widths:")
    print(f"    COMPILE:  {PIPELINE_COMPILE_WIDTH} workers")
    print(f"    GHIDRA:   {PIPELINE_GHIDRA_WIDTH} workers")
    print(f"    SUMMARY:  {PIPELINE_SUMMARY_WIDTH} workers (LLM)")
    print(f"    VEXHELIX: {PIPELINE_VEXHELIX_WIDTH} workers (LLM)")
    print(f"  Incremental saves: {incremental_save_dir}")
    print(f"{'='*70}\n")
    
    # Create queues
    compile_q = Queue()
    ghidra_q = Queue()
    summary_q = Queue()
    vexhelix_q = Queue()
    
    # Results storage
    results = []
    results_lock = threading.Lock()
    counters = {'active': 0, 'completed': 0}
    
    # Dropped counter
    dropped_counter = {'compile': 0, 'ghidra': 0, 'summary': 0}
    counter_lock = threading.Lock()
    
    # Start workers
    all_threads = []
    
    # Stage 1: Compile
    for _ in range(PIPELINE_COMPILE_WIDTH):
        worker_fn = _pipeline_compile_stage(compile_q, ghidra_q, temp_base_dir, dropped_counter, counter_lock)
        t = threading.Thread(target=worker_fn, daemon=True)
        t.start()
        all_threads.append(('compile', t))
    
    # Stage 2: Ghidra
    for _ in range(PIPELINE_GHIDRA_WIDTH):
        worker_fn = _pipeline_ghidra_stage(ghidra_q, summary_q, dropped_counter, counter_lock)
        t = threading.Thread(target=worker_fn, daemon=True)
        t.start()
        all_threads.append(('ghidra', t))
    
    # Stage 3: Summary
    for _ in range(PIPELINE_SUMMARY_WIDTH):
        worker_fn = _pipeline_summary_stage(summary_q, vexhelix_q, dropped_counter, counter_lock)
        t = threading.Thread(target=worker_fn, daemon=True)
        t.start()
        all_threads.append(('summary', t))
    
    # Stage 4: VexHelix
    for _ in range(PIPELINE_VEXHELIX_WIDTH):
        worker_fn = _pipeline_vexhelix_stage(vexhelix_q, results, results_lock, counters, total, incremental_save_dir)
        t = threading.Thread(target=worker_fn, daemon=True)
        t.start()
        all_threads.append(('vexhelix', t))
    
    # Feed items
    for item in batch_items:
        compile_q.put(item)
    
    # Drain stages
    compile_q.join()
    for _ in range(PIPELINE_COMPILE_WIDTH):
        compile_q.put(PIPELINE_DONE)
    
    ghidra_q.join()
    for _ in range(PIPELINE_GHIDRA_WIDTH):
        ghidra_q.put(PIPELINE_DONE)
    
    summary_q.join()
    for _ in range(PIPELINE_SUMMARY_WIDTH):
        summary_q.put(PIPELINE_DONE)
    
    vexhelix_q.join()
    for _ in range(PIPELINE_VEXHELIX_WIDTH):
        vexhelix_q.put(PIPELINE_DONE)
    
    # Wait for threads
    for stage_name, t in all_threads:
        t.join(timeout=5.0)
    
    # Summary
    total_dropped = dropped_counter['compile'] + dropped_counter['ghidra'] + dropped_counter['summary']
    equivalent_count = sum(1 for r in results 
                          if r['functions'] and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    
    bogus_results = [r for r in results if r.get('obfuscation_type') == 'bogus']
    cff_results = [r for r in results if r.get('obfuscation_type') == 'cff']
    bogus_equiv = sum(1 for r in bogus_results 
                      if r['functions'] and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    cff_equiv = sum(1 for r in cff_results 
                    if r['functions'] and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    
    print(f"\n{'='*70}")
    print(f"[PIPELINED V8] Complete!")
    print(f"{'='*70}")
    print(f"  Processed: {len(results)}/{total}")
    if total_dropped > 0:
        print(f"  Dropped: {total_dropped} (compile:{dropped_counter['compile']}, ghidra:{dropped_counter['ghidra']}, summary:{dropped_counter['summary']})")
    print(f"  Equivalent: {equivalent_count}/{len(results)} ({100*equivalent_count/len(results) if results else 0:.0f}%)")
    print(f"    Bogus: {bogus_equiv}/{len(bogus_results)}")
    print(f"    CFF:   {cff_equiv}/{len(cff_results)}")
    print(f"  LLM Dispatcher Stats:")
    print(f"    Total dispatched: {llm_interface.get_stats()['total_dispatched']}")
    print(f"  Output: {incremental_save_dir}")
    print(f"{'='*70}\n")
    
    # Combine results
    v4_5_save_dir = incremental_save_dir / "v4_5"
    v8_save_dir = incremental_save_dir / "v8"
    
    for save_dir, label in [(v8_save_dir, "V8"), (v4_5_save_dir, "V4.5")]:
        combined_file = save_dir / "combined_results.json"
        try:
            combined_results = []
            for json_file in sorted(save_dir.glob("func_*.json")):
                with open(json_file, 'r') as f:
                    combined_results.append(json.load(f))
            combined_results.sort(key=lambda x: (x.get('index', 0), x.get('obfuscation_type', '')))
            with open(combined_file, 'w') as f:
                json.dump(combined_results, f, indent=2)
            print(f"[SAVE] Combined {len(combined_results)} {label} results into {combined_file}")
        except Exception as e:
            print(f"[SAVE] Warning: Failed to combine {label} results: {e}")
    
    return results, incremental_save_dir


def process_obfuscation_dataset(start_index: int = 0, limit: int = None):
    """Main entry point for processing obfuscation dataset."""
    # Create timestamped output directory
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    incremental_save_dir = OUTPUT_DIR / f"run_{timestamp}"
    incremental_save_dir.mkdir(parents=True, exist_ok=True)
    
    # Load and filter dataset
    dataset = load_obfuscation_dataset()
    if not dataset:
        print("[ERROR] Failed to load dataset")
        return
    
    filtered_dataset = filter_dataset_for_collector(dataset)
    
    # Apply start_index and limit
    if limit:
        filtered_dataset = filtered_dataset[start_index:start_index + limit]
    else:
        filtered_dataset = filtered_dataset[start_index:]
    
    # Count by type
    bogus_count = sum(1 for d in filtered_dataset if d['obfuscation_type'] == 'bogus')
    cff_count = sum(1 for d in filtered_dataset if d['obfuscation_type'] == 'cff')
    o2_count = sum(1 for d in filtered_dataset if d['opt'] == 'O2')
    
    print(f"\n{'='*70}")
    print(f"Obfuscation Collector V8 - DUAL LLM ENDPOINTS")
    print(f"{'='*70}")
    print(f"Processing {len(filtered_dataset)} entries via STREAMING PIPELINE")
    print(f"  - Start index: {start_index}")
    print(f"  - Bogus: {bogus_count}, CFF: {cff_count}")
    print(f"  - O2: {o2_count}")
    print(f"LLM Endpoints (round-robin):")
    for i, endpoint in enumerate(LLM_ENDPOINTS):
        print(f"  [{i+1}] {endpoint}")
    print(f"Model: {config['llm']['vllm_model_name']}")
    print(f"VexHelix API: {VEXHELIX_API_URL}")
    print(f"Output directory: {incremental_save_dir}")
    print(f"{'='*70}\n")
    
    all_results = []
    
    with tempfile.TemporaryDirectory() as temp_base_dir:
        temp_base_path = Path(temp_base_dir)
        results, save_dir = process_batch_pipelined(
            filtered_dataset, temp_base_path, incremental_save_dir
        )
        all_results = results
    
    # Final summary
    equivalent_count = sum(1 for r in all_results 
                          if r.get('functions') and r['functions'][0].get('optimization_stats', {}).get('final_result') == 'equivalent')
    
    print(f"\n{'='*70}")
    print(f"Processing complete!")
    print(f"  Total processed: {len(all_results)}/{len(filtered_dataset)}")
    print(f"  Total equivalent (V8): {equivalent_count}/{len(all_results) if all_results else 0}")
    print(f"  Results directory: {incremental_save_dir}")
    print(f"  V4.5 results: {incremental_save_dir / 'v4_5' / 'combined_results.json'}")
    print(f"  V8 results: {incremental_save_dir / 'v8' / 'combined_results.json'}")
    print(f"{'='*70}\n")


def check_vexhelix_api() -> bool:
    """Check if VexHelix API is reachable and healthy."""
    try:
        response = requests.get(f"{VEXHELIX_API_URL}/health", timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"✓ VexHelix API is healthy at {VEXHELIX_API_URL}")
            print(f"  Version: {data.get('version', 'unknown')}")
            return True
        else:
            print(f"⚠ VexHelix API returned unexpected status: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"✗ Cannot connect to VexHelix API at {VEXHELIX_API_URL}")
        return False
    except Exception as e:
        print(f"✗ Error checking VexHelix API: {e}")
        return False


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Obfuscation Collector V8 - DUAL LLM ENDPOINTS")
    parser.add_argument("--start", type=int, default=0, help="Starting index (default: 0)")
    parser.add_argument("--limit", type=int, default=None, help="Maximum items to process")
    parser.add_argument("--skip-api-check", action="store_true", help="Skip VexHelix API check")
    args = parser.parse_args()
    
    # Check dataset exists
    if not OBFUSCATION_DATASET_PATH.exists():
        print(f"✗ Dataset not found: {OBFUSCATION_DATASET_PATH}")
        return
    
    # Check Gemini signatures exist
    if not GEMINI_SIGNATURES_PATH.exists():
        print(f"✗ Gemini signatures not found: {GEMINI_SIGNATURES_PATH}")
        print("  Run preprocess_obfuscation_signatures.py first")
        return
    
    # Check LLM endpoints
    print(f"Checking dual vLLM endpoints...")
    for i, endpoint in enumerate(LLM_ENDPOINTS):
        try:
            response = requests.get(f"{endpoint}/health", timeout=5)
            print(f"✓ Endpoint [{i+1}] {endpoint} is reachable")
        except Exception as e:
            print(f"⚠ Endpoint [{i+1}] {endpoint} check failed: {e}")
    
    # Check VexHelix API
    if not args.skip_api_check:
        if not check_vexhelix_api():
            print("\n⚠ VexHelix API is not available.")
            print("  Start with: cd /path/to/vexhelix && python -m vexhelix.api.server")
            print("  Or use --skip-api-check to continue anyway")
            return
    
    process_obfuscation_dataset(args.start, args.limit)


if __name__ == "__main__":
    main()
