# MissionDecompile V7 - TypeForge + VexHelix Integration

## Summary

V7 integrates **TypeForge type constraints** into the pipelined V6 architecture because **VexHelix cannot verify type correctness** - only semantic equivalence for explored execution paths.

## Key Changes from V6 to V7

### 1. Type Constraint Integration
- `get_type_constraints(data)` loads TypeForge constraints from `corpus_path/typeforge/func_{index}/`
- Type constraints included in ALL prompts: initial, static repair, semantic repair
- New `format_type_constraints_for_prompt()` formats constraints for LLM consumption

### 2. Enhanced Prompts
- **Initial Prompt**: Now includes type constraints to guide correct return/param types
- **Static Repair Prompt**: Uses type constraints to help fix type-related compilation errors
- **Semantic Repair Prompt**: Addresses BOTH semantic AND type errors (critical fix!)

### 3. config.yaml Update
The `semantic_repair` prompt now explicitly handles:
1. Semantic/logic errors (detected by VexHelix)
2. Type errors (may NOT be detected by VexHelix but still incorrect)

---

## V4 vs V6 vs old_v7 vs new V7 Comparison

| Feature | V4 | V6 | old_v7 | V7 (new) |
|---------|----|----|--------|----------|
| TypeForge constraints | ✓ | ✗ | ✓ | ✓ |
| VexHelix verification | ✗ | ✓ | ✓ | ✓ |
| Pipelined execution | ✗ | ✓ | ✗ | ✓ |
| Assembly in prompts | ✗ | ✓ | ✗ | ✓ |
| Type-aware semantic repair | ✗ | ✗ | Partial | ✓ |
| Stagnation detection | ✗ | ✓ | ✗ | ✓ |
| Retry with backoff | ✗ | ✓ | ✗ | ✓ |

---

## TypeForge vs Typehoon Comparison

| Aspect | TypeForge | Typehoon (angr) |
|--------|-----------|-----------------|
| **Availability** | Pre-analyzed binaries only | Any binary angr can load |
| **Detail Level** | High (struct layouts, field offsets) | Medium (basic types) |
| **Integration** | Files in `typeforge/func_{idx}/` | Built into angr decompiler |
| **Coverage** | Limited (requires preprocessing) | Universal (on-the-fly) |
| **Use Case** | Primary type source when available | Fallback when TypeForge unavailable |

### Typehoon POC Created
See `MissionDecompile-v7/utils/typehoon_poc.py` for:
- Extraction via angr's Decompiler analysis
- Formatting for LLM prompts
- Comparison/merging with TypeForge

---

## Logical Audit Results

### old_v7 Issues Found:
1. ✓ Includes TypeForge but NOT assembly in initial prompt
2. ✓ No stagnation detection (can loop forever)
3. ✓ No retry logic for VexHelix API failures
4. ✓ Sequential processing (not pipelined)

### V6 Issues Found:
1. ✓ Missing TypeForge integration entirely
2. ✓ Semantic repair prompt doesn't mention types

### V7 Fixes:
- Combines V6's pipelined architecture + retry logic
- Adds TypeForge from old_v7
- Enhanced semantic_repair prompt for type errors
- Tracking of TypeForge availability in stats

---

## Files Created/Modified

### Created:
- `MissionDecompile-v7/evaluator/batched_humaneval_collector_v7.py` - Main V7 collector
- `MissionDecompile-v7/utils/typehoon_poc.py` - Typehoon POC

### Modified:
- `MissionDecompile-v7/config.yaml` - Enhanced semantic_repair prompt

---

## Usage

```bash
# Start VexHelix server first
cd VexHelix && python -m vexhelix.api.server --port 8001

# Run V7 pipeline
cd MissionDecompile-v7/evaluator
python batched_humaneval_collector_v7.py --start 0 --limit 20
```

Output: `output/humaneval-decompile/batched_enriched_humaneval_decompile_v7.json`
