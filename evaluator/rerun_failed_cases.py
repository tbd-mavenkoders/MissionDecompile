#!/usr/bin/env python3
"""
Rerun Failed Cases Script

Reruns only the cases that failed due to LLM errors, VexHelix errors, or other issues.
Reads the existing results directory and identifies cases to retry.

Usage:
    python rerun_failed_cases.py --run-dir <run_directory> [--error-types llm_error vexhelix_error] [--limit N]
    
Examples:
    # Rerun all LLM error cases
    python rerun_failed_cases.py --run-dir output/exebench/run_20260206_011917 --error-types llm_error
    
    # Rerun both LLM and VexHelix errors
    python rerun_failed_cases.py --run-dir output/exebench/run_20260206_011917 --error-types llm_error vexhelix_error
    
    # Rerun with limit
    python rerun_failed_cases.py --run-dir output/exebench/run_20260206_011917 --error-types llm_error --limit 100
"""

import argparse
import json
import os
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path for imports
SCRIPT_DIR = Path(__file__).parent
VERITAS_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(VERITAS_DIR))

# Delayed imports (after path setup)
def get_imports():
    from evaluator.pipelined_exebench_collector_v8 import (
        process_batch_pipelined_v7,
        corpus_path,
        get_unique_id
    )
    from utils.llm_interface import set_global_rate_limit
    return process_batch_pipelined_v7, corpus_path, get_unique_id, set_global_rate_limit


def find_failed_cases(run_dir: Path, error_types: list) -> list:
    """
    Scan the v8 results directory and find cases with specified error types.
    
    Args:
        run_dir: Path to the run directory (e.g., output/exebench/run_20260206_011917)
        error_types: List of error types to filter for (e.g., ['llm_error', 'vexhelix_error'])
    
    Returns:
        List of unique_ids (e.g., ['219_O3', '224_O0', ...])
    """
    v8_dir = run_dir / "v8"
    if not v8_dir.exists():
        print(f"Error: v8 results directory not found: {v8_dir}")
        return []
    
    failed_cases = []
    
    for filename in os.listdir(v8_dir):
        if not filename.endswith('.json'):
            continue
        
        try:
            filepath = v8_dir / filename
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            if data.get('functions'):
                stats = data['functions'][0].get('optimization_stats', {})
                result = stats.get('final_result', 'unknown')
                
                if result in error_types:
                    # Extract unique_id from filename: func_XXX_OY.json -> XXX_OY
                    unique_id = filename.replace('func_', '').replace('.json', '')
                    failed_cases.append(unique_id)
        except Exception as e:
            print(f"Warning: Could not parse {filename}: {e}")
    
    return sorted(failed_cases, key=lambda x: (int(x.split('_')[0]), x.split('_')[1]))


def load_exebench_data_for_cases(unique_ids: set, corpus_path: Path, get_unique_id) -> list:
    """
    Load exebench data only for the specified unique_ids.
    
    Args:
        unique_ids: Set of unique_ids to load (e.g., {'219_O3', '224_O0'})
        corpus_path: Path to the corpus directory
        get_unique_id: Function to generate unique ID from item
    
    Returns:
        List of exebench data dicts for matching cases
    """
    json_path = corpus_path / "exebench_data.json"
    
    if not json_path.exists():
        print(f"Error: exebench_data.json not found at {json_path}")
        return []
    
    print(f"Loading exebench data from {json_path}...")
    with open(json_path, 'r') as f:
        all_data = json.load(f)
    
    # Filter to only requested cases
    filtered_data = []
    for item in all_data:
        item_unique_id = get_unique_id(item)
        if item_unique_id in unique_ids:
            # Add unique_id to item for tracking
            item['unique_id'] = item_unique_id
            filtered_data.append(item)
    
    return filtered_data


def main():
    parser = argparse.ArgumentParser(description='Rerun failed cases from a previous run')
    parser.add_argument('--run-dir', type=str, required=True,
                        help='Path to the run directory (e.g., output/exebench/run_20260206_011917)')
    parser.add_argument('--error-types', nargs='+', default=['llm_error'],
                        choices=['llm_error', 'vexhelix_error', 'vexhelix_timeout', 
                                'max_iterations_not_compilable', 'max_iterations_compilable',
                                'stagnant_divergences', 'unknown'],
                        help='Error types to rerun (default: llm_error)')
    parser.add_argument('--limit', type=int, default=None,
                        help='Maximum number of cases to rerun')
    parser.add_argument('--rate-limit', type=int, default=150,
                        help='LLM requests per minute (default: 150)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Only show what would be rerun, do not actually run')
    parser.add_argument('--output-dir', type=str, default=None,
                        help='Output directory for rerun results (default: <run-dir>_rerun_<timestamp>)')
    
    args = parser.parse_args()
    
    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        print(f"Error: Run directory not found: {run_dir}")
        sys.exit(1)
    
    # Find failed cases
    print(f"\n{'='*70}")
    print(f"RERUN FAILED CASES")
    print(f"{'='*70}")
    print(f"Run directory: {run_dir}")
    print(f"Error types to rerun: {args.error_types}")
    
    failed_cases = find_failed_cases(run_dir, args.error_types)
    
    if not failed_cases:
        print("\nNo failed cases found matching the specified error types.")
        sys.exit(0)
    
    print(f"\nFound {len(failed_cases)} failed cases")
    
    # Apply limit if specified
    if args.limit and args.limit < len(failed_cases):
        failed_cases = failed_cases[:args.limit]
        print(f"Limited to {args.limit} cases")
    
    # Show sample
    print(f"\nSample cases to rerun:")
    for case in failed_cases[:10]:
        print(f"  - {case}")
    if len(failed_cases) > 10:
        print(f"  ... and {len(failed_cases) - 10} more")
    
    if args.dry_run:
        print("\n[DRY RUN] Would rerun the above cases. Use without --dry-run to execute.")
        sys.exit(0)
    
    # Import heavy modules only when actually running
    print("\nLoading modules...")
    process_batch_pipelined_v7, corpus_path, get_unique_id, set_global_rate_limit = get_imports()
    
    # Load exebench data for failed cases
    unique_ids = set(failed_cases)
    exebench_data = load_exebench_data_for_cases(unique_ids, corpus_path, get_unique_id)
    
    if not exebench_data:
        print("Error: Could not load any exebench data for failed cases")
        sys.exit(1)
    
    print(f"\nLoaded {len(exebench_data)} items from exebench data")
    
    # Check for Gemini signatures (required for V8)
    gemini_sigs_path = VERITAS_DIR.parent / "references" / "gemini_signatures_preprocessed.json"
    if gemini_sigs_path.exists():
        print(f"Loading Gemini signatures from {gemini_sigs_path}...")
        with open(gemini_sigs_path, 'r') as f:
            gemini_sigs = json.load(f)
        
        # Filter to only items with Gemini signatures
        valid_keys = set(gemini_sigs.keys())
        exebench_data = [d for d in exebench_data if get_unique_id(d) in valid_keys]
        print(f"Filtered to {len(exebench_data)} items with Gemini signatures")
    
    if not exebench_data:
        print("Error: No valid cases to rerun after filtering")
        sys.exit(1)
    
    # Setup output directory
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = run_dir.parent / f"{run_dir.name}_rerun_{timestamp}"
    
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nOutput directory: {output_dir}")
    
    # Set rate limit
    set_global_rate_limit(args.rate_limit)
    
    # Create temp directory
    import tempfile
    temp_base = Path(tempfile.mkdtemp(prefix="exebench_rerun_"))
    
    print(f"\n{'='*70}")
    print(f"STARTING RERUN")
    print(f"{'='*70}")
    print(f"Cases to process: {len(exebench_data)}")
    print(f"Temp directory: {temp_base}")
    print(f"Output directory: {output_dir}")
    
    # Run the pipeline
    try:
        results = process_batch_pipelined_v7(
            exebench_data,
            temp_base,
            output_dir
        )
        
        print(f"\n{'='*70}")
        print(f"RERUN COMPLETE")
        print(f"{'='*70}")
        print(f"Processed: {len(results)} cases")
        print(f"Results saved to: {output_dir}")
        
        # Quick summary
        from collections import Counter
        result_counts = Counter()
        for r in results:
            if r.get('functions'):
                final_result = r['functions'][0].get('optimization_stats', {}).get('final_result', 'unknown')
                result_counts[final_result] += 1
        
        print("\nResult distribution:")
        for result, count in result_counts.most_common():
            print(f"  {result}: {count}")
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Partial results saved to:", output_dir)
    except Exception as e:
        print(f"\nError during rerun: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup temp directory
        import shutil
        try:
            shutil.rmtree(temp_base)
        except:
            pass


if __name__ == "__main__":
    main()
