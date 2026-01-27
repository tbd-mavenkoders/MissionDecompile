#!/usr/bin/env python3
"""
Test script for V7 Pipeline - 12 cases (6 C + 6 C++)

This script runs batched_humaneval_collector_v7.py on a subset of 12 test cases:
- 6 C programs (indices 670-675, which map to C indices 14-19)
- 6 C++ programs (indices 14-19)

Usage:
    python tests/test_v7_12cases.py [--rate-limit 150]

Requirements:
    - VexHelix API running at http://127.0.0.1:8001
    - vLLM server running at http://127.0.0.1:8000
    - Ghidra installed and configured
    - cxxfilt installed (pip install cxxfilt) for C++ demangling
"""

import sys
import json
import time
import argparse
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml

def create_subset_dataset(input_json: Path, output_json: Path, c_indices: list, cpp_indices: list):
    """Create a subset dataset with specified indices, preserving original indices."""
    with open(input_json, 'r') as f:
        full_data = json.load(f)
    
    subset = []
    
    # Add C++ items first (indices 14-19)
    for idx in cpp_indices:
        if idx < len(full_data):
            item = full_data[idx].copy()
            item['original_index'] = idx  # Preserve original corpus index
            subset.append(item)
    
    # Add C items (indices 670-675 in corpus = C indices 14-19)
    for idx in c_indices:
        if idx < len(full_data):
            item = full_data[idx].copy()
            item['original_index'] = idx  # Preserve original corpus index
            subset.append(item)
    
    with open(output_json, 'w') as f:
        json.dump(subset, f, indent=2)
    
    c_count = sum(1 for item in subset if item.get('language') == 'c')
    cpp_count = sum(1 for item in subset if item.get('language') == 'cpp')
    print(f"Created subset dataset: {len(subset)} items (C: {c_count}, C++: {cpp_count})")
    
    # Print the actual indices being tested
    print(f"\nTest items:")
    for item in subset:
        lang = item.get('language', 'unknown')
        orig_idx = item.get('original_index', '?')
        print(f"  - Original index {orig_idx} ({lang})")
    
    return subset


def main():
    print("=" * 70)
    print("V7 Pipeline Test - 12 Cases (6 C + 6 C++)")
    print("=" * 70)
    
    # Load config
    config_path = Path(__file__).resolve().parent.parent / "config.yaml"
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    corpus_path = Path(config['humaneval']['corpus_path'])
    input_json = corpus_path / "humaneval-decompile.json"
    
    # Create subset dataset
    # C items: corpus indices 670-675 (C programs at relative indices 14-19)
    # C++ items: corpus indices 14-19 (C++ programs)
    # 
    # The humaneval-decompile corpus structure:
    # - Indices 0-655: C++ programs (index 0 = C++ #0, index 14 = C++ #14, etc.)
    # - Indices 656+: C programs (index 656 = C #0, index 670 = C #14, etc.)
    
    cpp_indices = list(range(14, 20))    # C++ indices 14-19 (6 items)
    c_indices = list(range(670, 676))    # C indices 14-19 (corpus 670-675, 6 items)
    
    print(f"\nTest configuration:")
    print(f"  C++ corpus indices: {cpp_indices[0]}-{cpp_indices[-1]} (C++ #14-19, {len(cpp_indices)} items)")
    print(f"  C corpus indices: {c_indices[0]}-{c_indices[-1]} (C #14-19, {len(c_indices)} items)")
    
    # Create temp subset file
    test_output_dir = Path(__file__).resolve().parent / "v7_test_output"
    test_output_dir.mkdir(parents=True, exist_ok=True)
    
    subset_json = test_output_dir / "test_subset_12.json"
    subset_data = create_subset_dataset(input_json, subset_json, c_indices, cpp_indices)
    
    # Parse arguments
    parser = argparse.ArgumentParser(description='V7 Pipeline Test - 12 Cases')
    parser.add_argument('--rate-limit', type=int, default=150,
                        help='Rate limit for LLM requests per minute (default: 150)')
    args = parser.parse_args()
    
    # Import and run the v7 collector
    print("\nImporting V7 collector...")
    try:
        from evaluator.batched_humaneval_collector_v7 import (
            check_vexhelix_api,
            process_batch,
            llm_interface,
            VEXHELIX_API_URL,
            corpus_path as v7_corpus_path,
            get_typehoon_stats,
            reset_typehoon_stats
        )
        from utils.llm_interface import set_global_rate_limit, get_rate_limiter_stats
        import tempfile
        
        # Set rate limit
        set_global_rate_limit(args.rate_limit)
        print(f"\n✓ Rate limit set to {args.rate_limit} requests/minute")
        
        # Reset Typehoon stats for clean tracking
        reset_typehoon_stats()
        
        # Check VexHelix
        print(f"\nChecking VexHelix API at {VEXHELIX_API_URL}...")
        if not check_vexhelix_api():
            print("\n⚠ VexHelix API is not available!")
            print("  Please start VexHelix server first:")
            print("  cd /path/to/vexhelix && python -m vexhelix.api.server")
            return 1
        
        print("\n✓ VexHelix API is healthy")
        
        # Add sequential index for processing (but preserve original_index)
        for i, item in enumerate(subset_data):
            item['index'] = i  # Sequential index for processing
            # original_index already set in create_subset_dataset
        
        # Process in a single batch
        print(f"\n{'='*70}")
        print(f"Starting V7 pipeline processing...")
        print(f"{'='*70}")
        
        start_time = time.time()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            results = process_batch(subset_data, temp_path)
        
        duration = time.time() - start_time
        
        # Analyze results
        print(f"\n{'='*70}")
        print(f"V7 TEST RESULTS - 12 Cases")
        print(f"{'='*70}")
        
        total = len(results)
        equivalent = 0
        compilable = 0
        c_equiv = 0
        cpp_equiv = 0
        c_total = 0
        cpp_total = 0
        
        # Detailed results per item
        print(f"\nDetailed results:")
        for prog in results:
            orig_idx = prog.get('original_index', '?')
            lang = prog.get('language', 'c')
            
            for func in prog.get('functions', []):
                stats = func.get('optimization_stats', {})
                result = stats.get('final_result', 'unknown')
                divergences = stats.get('divergence_history', [])
                
                if lang == 'c':
                    c_total += 1
                else:
                    cpp_total += 1
                
                is_equiv = result == 'equivalent'
                if is_equiv:
                    equivalent += 1
                    if lang == 'c':
                        c_equiv += 1
                    else:
                        cpp_equiv += 1
                
                is_compilable = result in ['equivalent', 'max_iterations_compilable', 'stagnant_divergences', 'vexhelix_timeout']
                if is_compilable:
                    compilable += 1
                
                status = "✓" if is_equiv else "✗"
                div_str = f"divergences: {divergences}" if divergences else ""
                print(f"  {status} Index {orig_idx} ({lang}): {result} {div_str}")
        
        print(f"\n{'='*70}")
        print(f"SUMMARY")
        print(f"{'='*70}")
        print(f"\nProcessed: {total} programs")
        print(f"Duration: {duration:.1f} seconds ({duration/60:.1f} minutes)")
        print(f"\nEquivalent (VexHelix verified): {equivalent}/{total} ({100*equivalent/total if total else 0:.1f}%)")
        print(f"  - C:   {c_equiv}/{c_total} ({100*c_equiv/c_total if c_total else 0:.1f}%)")
        print(f"  - C++: {cpp_equiv}/{cpp_total} ({100*cpp_equiv/cpp_total if cpp_total else 0:.1f}%)")
        print(f"\nCompilable: {compilable}/{total} ({100*compilable/total if total else 0:.1f}%)")
        
        # Save results with timestamp
        results_file = test_output_dir / f"v7_test_12cases_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nResults saved to: {results_file}")
        
        # Summary per result type
        result_counts = {}
        for prog in results:
            for func in prog.get('functions', []):
                result = func.get('optimization_stats', {}).get('final_result', 'unknown')
                result_counts[result] = result_counts.get(result, 0) + 1
        
        print(f"\nResult breakdown:")
        for result, count in sorted(result_counts.items(), key=lambda x: -x[1]):
            print(f"  {result}: {count}")
        
        # Print rate limiter stats
        rate_stats = get_rate_limiter_stats()
        print(f"\nRate limiter stats:")
        print(f"  Total LLM requests: {rate_stats.get('total_requests', 0)}")
        wait_time = rate_stats.get('total_wait_time_seconds', rate_stats.get('total_wait_time', 0))
        print(f"  Total wait time: {wait_time:.1f}s")
        current_rate = rate_stats.get('current_window_requests', 0)
        max_rpm = rate_stats.get('max_rpm', rate_stats.get('max_requests_per_minute', 150))
        print(f"  Current window: {current_rate} requests (limit: {max_rpm}/min)")
        
        # Print Typehoon stats (fallback when TypeForge unavailable)
        typehoon_stats = get_typehoon_stats()
        if typehoon_stats['called'] > 0:
            print(f"\nTypehoon fallback stats:")
            print(f"  Called (TypeForge unavailable): {typehoon_stats['called']}")
            print(f"  Success: {typehoon_stats['success']}")
            print(f"  Failed: {typehoon_stats['failed']}")
            if typehoon_stats['failed_indices']:
                print(f"  Failed indices: {typehoon_stats['failed_indices'][:20]}{'...' if len(typehoon_stats['failed_indices']) > 20 else ''}")
        else:
            print(f"\nTypehoon: Not used (TypeForge available for all cases)")
        
        print(f"\n{'='*70}")
        print(f"V7 TEST COMPLETE - 12 Cases")
        print(f"{'='*70}")
        
        return 0
        
    except ImportError as e:
        print(f"\n✗ Import error: {e}")
        print("  Make sure you're running from the MissionDecompile-v7 directory")
        return 1
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
