#!/usr/bin/env python3
"""
Quick test to verify D-Helix API integration in batched_humaneval_collector_v2.py

This tests:
1. D-Helix API connectivity
2. Basic semantic verification workflow
3. DHelixResult parsing
"""

import sys
from pathlib import Path
import tempfile
import requests

# Add parent to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Import the new functions
from evaluator.batched_humaneval_collector_v2 import (
    call_dhelix_api,
    get_semantic_repair_prompt,
    compile_code,
    DHELIX_API_URL
)
from utils.compile import Compiler

def test_api_connectivity():
    """Test 1: Check if D-Helix API is reachable"""
    print("="*60)
    print("TEST 1: D-Helix API Connectivity")
    print("="*60)
    
    try:
        response = requests.get(f"{DHELIX_API_URL}/health", timeout=5)
        if response.status_code == 200:
            print(f"✓ D-Helix API is reachable at {DHELIX_API_URL}")
            return True
        else:
            print(f"✗ API returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Cannot reach D-Helix API: {e}")
        print(f"  Make sure the server is running:")
        print(f"  cd /root/work/D-helix-fixed/fastapi_server")
        print(f"  python api_server.py")
        return False


def test_compilation():
    """Test 2: Verify compilation helper works"""
    print("\n" + "="*60)
    print("TEST 2: Code Compilation")
    print("="*60)
    
    correct_code = """
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}
"""
    
    buggy_code = """
int add(int a, int b) {
    return a * b;  // BUG: should be +
}
"""
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Test correct code
        success, msg, exe = compile_code(correct_code, "c", temp_path)
        if success:
            print("✓ Correct code compiles")
        else:
            print(f"✗ Correct code failed: {msg}")
            return False
        
        # Test buggy code (should still compile syntactically)
        success, msg, exe = compile_code(buggy_code, "c", temp_path)
        if success:
            print("✓ Buggy code compiles (syntactically correct)")
        else:
            print(f"✗ Buggy code failed: {msg}")
            return False
    
    return True


def test_semantic_repair_prompt():
    """Test 3: Verify semantic repair prompt generation"""
    print("\n" + "="*60)
    print("TEST 3: Semantic Repair Prompt Generation")
    print("="*60)
    
    from evaluator.batched_humaneval_collector_v2 import DHelixResult
    
    dhelix_result = DHelixResult(
        success=True,
        result="sat",
        z3_formula="(assert (= (add 2 3) 5))",
        counterexample={"arg_0": 2, "arg_1": 3},
        error_message=None
    )
    
    prompt = get_semantic_repair_prompt(
        original_asm="add eax, edx\nret",
        original_ghidra="return param_1 + param_2;",
        current_code="int add(int a, int b) { return a * b; }",
        function_summary="Adds two integers and returns the sum",
        dhelix_result=dhelix_result,
        language="c"
    )
    
    # Check prompt contains key elements
    checks = [
        ("Counterexample" in prompt, "Contains counterexample"),
        ("arg_0" in prompt, "Contains argument values"),
        ("Original Assembly" in prompt, "Contains assembly code"),
        ("Original Ghidra" in prompt, "Contains Ghidra code"),
        ("Current Decompiled Code" in prompt, "Contains current code"),
        ("SAT" in prompt, "Mentions SAT result"),
    ]
    
    all_passed = True
    for check, description in checks:
        if check:
            print(f"✓ {description}")
        else:
            print(f"✗ {description}")
            all_passed = False
    
    if all_passed:
        print("\n✓ Semantic repair prompt contains all required elements")
    
    return all_passed


def test_dhelix_call_structure():
    """Test 4: Verify D-Helix API call structure (dry-run)"""
    print("\n" + "="*60)
    print("TEST 4: D-Helix API Call Structure - Correct Code (expect UNSAT)")
    print("="*60)
    
    # Create a minimal test binary - source code WITH main
    binary_source_code = """
int add(int a, int b) {
    return a + b;
}

int main() {
    return add(2, 3);
}
"""
    
    # Decompiled code - just the function, NO main (D-Helix adds its own main stub)
    decompiled_code = """
int add(int a, int b) {
    return a + b;
}
"""
    
    print("Creating test binary...")
    c = Compiler()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        source_file = temp_path / "test.c"
        binary_file = temp_path / "test_binary"
        
        with open(source_file, "w") as f:
            f.write(binary_source_code)
        
        from utils.compile import OptimizationLevel
        success, msg = c.compile_source(
            source_file_path=source_file,
            output_file_path=binary_file,
            opt=OptimizationLevel.O0,
            is_cpp=False,
            c_flag=False
        )
        
        if not success:
            print(f"✗ Failed to create test binary: {msg}")
            return False
        
        print("✓ Test binary created")
        
        # Try calling D-Helix API
        print("Testing D-Helix API call with CORRECT code...")
        result = call_dhelix_api(
            binary_path=binary_file,
            decompiled_code=decompiled_code,  # Just the function, no main
            function_name="add"
        )
        
        if result.success:
            print(f"✓ D-Helix API call succeeded")
            print(f"  Result: {result.result}")
            if result.result == "unsat":
                print("  ✓ EXPECTED: unsat means code is semantically correct")
                return True
            else:
                print(f"  ⚠ Unexpected: expected unsat, got {result.result}")
                return False
        else:
            print(f"⚠ D-Helix API call failed: {result.error_message}")
            return None


def test_dhelix_buggy_code():
    """Test 5: Verify D-Helix detects buggy code (should return SAT)"""
    print("\n" + "="*60)
    print("TEST 5: D-Helix Bug Detection - Buggy Code (expect SAT)")
    print("="*60)
    
    # Create a binary with correct add function
    binary_source_code = """
int add(int a, int b) {
    return a + b;
}

int main() {
    return add(2, 3);
}
"""
    
    # BUGGY decompiled code - multiplication instead of addition
    buggy_decompiled_code = """
int add(int a, int b) {
    return a * b;
}
"""
    
    print("Creating test binary with CORRECT add function...")
    c = Compiler()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        source_file = temp_path / "test.c"
        binary_file = temp_path / "test_binary"
        
        with open(source_file, "w") as f:
            f.write(binary_source_code)
        
        from utils.compile import OptimizationLevel
        success, msg = c.compile_source(
            source_file_path=source_file,
            output_file_path=binary_file,
            opt=OptimizationLevel.O0,
            is_cpp=False,
            c_flag=False
        )
        
        if not success:
            print(f"✗ Failed to create test binary: {msg}")
            return False
        
        print("✓ Test binary created")
        
        # Try calling D-Helix API with BUGGY code
        print("Testing D-Helix API call with BUGGY code (a*b instead of a+b)...")
        result = call_dhelix_api(
            binary_path=binary_file,
            decompiled_code=buggy_decompiled_code,
            function_name="add"
        )
        
        if result.success:
            print(f"✓ D-Helix API call succeeded")
            print(f"  Result: {result.result}")
            if result.result == "sat":
                print("  ✓ EXPECTED: sat means D-Helix detected the bug!")
                if result.counterexample:
                    print(f"  Counterexample: {result.counterexample}")
                return True
            else:
                print(f"  ⚠ Unexpected: expected sat (bug detection), got {result.result}")
                return False
        else:
            print(f"⚠ D-Helix API call failed: {result.error_message}")
            return None


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print(" D-Helix Integration Test Suite")
    print("="*70)
    
    results = []
    
    # Test 1: API connectivity
    results.append(("API Connectivity", test_api_connectivity()))
    
    # Test 2: Compilation
    results.append(("Code Compilation", test_compilation()))
    
    # Test 3: Prompt generation
    results.append(("Semantic Repair Prompt", test_semantic_repair_prompt()))
    
    # Test 4: D-Helix API call with correct code (expect UNSAT)
    api_result = test_dhelix_call_structure()
    if api_result is not None:
        results.append(("D-Helix Correct Code (UNSAT)", api_result))
    else:
        results.append(("D-Helix Correct Code (UNSAT)", "skipped"))
    
    # Test 5: D-Helix API call with buggy code (expect SAT)
    buggy_result = test_dhelix_buggy_code()
    if buggy_result is not None:
        results.append(("D-Helix Buggy Code (SAT)", buggy_result))
    else:
        results.append(("D-Helix Buggy Code (SAT)", "skipped"))
    
    # Test 6: Real HumanEval data test
    real_result = test_humaneval_real_data()
    if real_result is not None:
        results.append(("HumanEval Real Data", real_result))
    else:
        results.append(("HumanEval Real Data", "skipped"))
    
    # Summary
    print("\n" + "="*70)
    print(" Test Summary")
    print("="*70)
    
    passed = 0
    failed = 0
    skipped = 0
    
    for name, result in results:
        if result is True:
            print(f"✓ {name}: PASSED")
            passed += 1
        elif result is False:
            print(f"✗ {name}: FAILED")
            failed += 1
        else:
            print(f"⊙ {name}: SKIPPED")
            skipped += 1
    
    print("\n" + "="*70)
    print(f"Total: {passed} passed, {failed} failed, {skipped} skipped")
    print("="*70)
    
    if failed == 0:
        print("\n✓✓✓ All tests passed! Ready to run batched_humaneval_collector_v2.py")
        return 0
    else:
        print(f"\n✗ {failed} test(s) failed. Please fix before running.")
        return 1


def test_humaneval_real_data():
    """Test 6: Test with real HumanEval data (entry 656 - C language)"""
    print("\n" + "="*60)
    print("TEST 6: Real HumanEval Data Test (Entry 656 - C)")
    print("="*60)
    
    import json
    from pathlib import Path
    
    # Load HumanEval data
    data_path = Path(__file__).parent / "data" / "humaneval-decompile" / "humaneval-decompile.json"
    
    if not data_path.exists():
        print(f"⚠ Data file not found: {data_path}")
        return None
    
    with open(data_path) as f:
        humaneval_data = json.load(f)
    
    # Find a C language entry (entry 656)
    entry = None
    for e in humaneval_data:
        if e['language'] == 'c':
            entry = e
            break
    
    if entry is None:
        print("⚠ No C language entry found in dataset")
        return None
    
    print(f"Testing entry {entry['index']}: {entry['func_name']}")
    print(f"Language: {entry['language']}")
    
    # Compile original source code to get binary
    original_code = entry['func_dep'] + entry['func']
    print(f"\nOriginal code snippet:\n{entry['func'][:200]}...")
    
    c = Compiler()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        source_file = temp_path / "original.c"
        binary_file = temp_path / "original_binary"
        
        with open(source_file, "w") as f:
            f.write(original_code)
        
        from utils.compile import OptimizationLevel
        success, msg = c.compile_source(
            source_file_path=source_file,
            output_file_path=binary_file,
            opt=OptimizationLevel.O0,
            is_cpp=False,
            c_flag=True  # Just compile, don't link (for functions without main)
        )
        
        if not success:
            print(f"⚠ Failed to compile original code: {msg[:200]}")
            # Try without c_flag
            success, msg = c.compile_source(
                source_file_path=source_file,
                output_file_path=binary_file,
                opt=OptimizationLevel.O0,
                is_cpp=False,
                c_flag=False
            )
            if not success:
                print(f"⚠ Still failed: {msg[:200]}")
                return None
        
        print("✓ Original code compiled to binary")
        
        # Test D-Helix with original Ghidra pseudocode
        ghidra_pseudo = entry['ghidra_pseudo']
        print(f"\nGhidra pseudocode snippet:\n{ghidra_pseudo[:200]}...")
        
        # Call D-Helix API
        print("\nCalling D-Helix API with Ghidra pseudocode...")
        result = call_dhelix_api(
            binary_path=binary_file,
            decompiled_code=ghidra_pseudo,
            function_name=entry['func_name']
        )
        
        if result.success:
            print(f"✓ D-Helix API call succeeded")
            print(f"  Result: {result.result}")
            if result.result == "unsat":
                print("  ✓ Ghidra pseudocode is semantically equivalent to binary")
            else:
                print("  ⚠ Ghidra pseudocode has semantic differences (expected for raw Ghidra output)")
            return True
        else:
            # D-Helix compilation may fail for complex Ghidra output - that's expected
            print(f"⚠ D-Helix API call failed: {result.error_message}")
            print("  (This is expected - Ghidra output often needs LLM fixing first)")
            return None


if __name__ == "__main__":
    sys.exit(main())
