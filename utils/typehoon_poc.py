#!/usr/bin/env python3
"""
Typehoon POC - Type Constraint Extraction using angr's Typehoon

This is a proof-of-concept for using angr's built-in Typehoon type analysis
as an alternative/complement to TypeForge for extracting type constraints.

Typehoon vs TypeForge comparison:
=================================

TypeForge:
  - External tool, requires separate preprocessing
  - Outputs JSON files with variable types
  - Supports struct layouts and pointer types
  - Requires Ghidra preprocessing
  - More detailed type layouts for complex structs
  - Coverage: Only available for pre-analyzed binaries

Typehoon (angr):
  - Built into angr, runs at decompilation time
  - Available for ANY binary we load in VexHelix
  - Uses constraint-based type inference
  - Provides: return type, parameter types, local variable types
  - Can extract types on-the-fly during verification
  - Coverage: Universal (any binary angr can load)

Integration Strategy for V7:
============================
1. Primary: Use TypeForge if available (more detailed)
2. Fallback: Use Typehoon for binaries without TypeForge data
3. Combined: Merge both for maximum type information

V7 Enhancement: C++ name mangling support via cxxfilt
=====================================================
C++ binaries use name mangling (e.g., _Z5func0f -> func0(float))
This module now handles demangling to find C++ functions by base name.
"""

import angr
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

# Try to import cxxfilt for C++ name demangling (like VexHelix does)
try:
    import cxxfilt
    HAS_CXXFILT = True
except ImportError:
    HAS_CXXFILT = False


# =============================================================================
# C++ NAME MANGLING SUPPORT (inspired by VexHelix entangler.py)
# =============================================================================

def is_cpp_mangled_name(name: str) -> bool:
    """Check if a name appears to be a C++ mangled name."""
    if not name:
        return False
    return name.startswith('_Z') or name.startswith('__Z')


def demangle_cpp_name(name: str) -> str:
    """
    Demangle a C++ mangled name to get the base function name.
    
    Example: "_Z5func0f" -> "func0"
    """
    if not HAS_CXXFILT:
        return name
    if not is_cpp_mangled_name(name):
        return name
    try:
        demangled = cxxfilt.demangle(name)
        # Extract just the function name without parameters
        # e.g., "func0(float)" -> "func0"
        if '(' in demangled:
            demangled = demangled.split('(')[0]
        # Replace :: with _ for class methods (namespace::func -> namespace_func)
        demangled = demangled.replace('::', '_')
        return demangled
    except:
        return name


def find_function_by_name(project: angr.Project, cfg, func_name: str):
    """
    Find a function in the binary, handling C++ name mangling.
    
    Tries multiple strategies:
    1. Direct name match in CFG functions
    2. Search for mangled name that demangles to func_name
    3. Search by symbol table with demangling
    
    Args:
        project: The angr project
        cfg: The CFG analysis result
        func_name: Function name to search for (e.g., "func0")
        
    Returns:
        Function object if found, None otherwise
    """
    # Strategy 1: Direct name match
    for f in cfg.functions.values():
        if f.name == func_name:
            return f
    
    # Strategy 2: Check knowledge base
    if func_name in project.kb.functions:
        return project.kb.functions[func_name]
    
    # Strategy 3: Search all functions for mangled name that demangles to func_name
    for f in cfg.functions.values():
        if not f.name:
            continue
        
        # Check if this is a mangled version of our function
        if is_cpp_mangled_name(f.name):
            demangled = demangle_cpp_name(f.name)
            if demangled == func_name or demangled.endswith(func_name):
                return f
        
        # Also check suffix match for Ghidra-style names (FUN_, sub_)
        if f.name.endswith(func_name):
            return f
    
    # Strategy 4: Search symbol table with demangling
    for sym in project.loader.symbols:
        if not sym.name or not sym.is_function:
            continue
        
        # Direct match
        if sym.name == func_name:
            # Find function by address
            if sym.rebased_addr in cfg.functions:
                return cfg.functions[sym.rebased_addr]
        
        # Demangled match
        if is_cpp_mangled_name(sym.name):
            demangled = demangle_cpp_name(sym.name)
            if demangled == func_name or demangled.endswith(func_name):
                if sym.rebased_addr in cfg.functions:
                    return cfg.functions[sym.rebased_addr]
    
    return None


def list_available_functions(project: angr.Project, cfg) -> List[Dict]:
    """
    List all functions in the binary with their mangled/demangled names.
    Useful for debugging when function lookup fails.
    """
    functions = []
    
    for f in cfg.functions.values():
        entry = {
            "name": f.name,
            "address": hex(f.addr) if f.addr else None,
        }
        
        # Add demangled name if different
        if f.name and is_cpp_mangled_name(f.name):
            entry["demangled"] = demangle_cpp_name(f.name)
        
        functions.append(entry)
    
    return functions


@dataclass
class TypehoonConstraint:
    """Represents a type constraint extracted by Typehoon."""
    variable_name: str
    variable_type: str
    source: str  # "parameter", "local", "return"
    confidence: str  # "high", "medium", "low"
    details: Optional[Dict] = None


def extract_typehoon_constraints(binary_path: str, function_name: str = "func0") -> Dict:
    """
    Extract type constraints from a binary using angr's Typehoon.
    
    V7 Enhancement: Now handles C++ name mangling via cxxfilt.
    
    Args:
        binary_path: Path to the compiled binary
        function_name: Name of the function to analyze (default: func0)
    
    Returns:
        Dict containing extracted type constraints
    """
    result = {
        "success": False,
        "function_name": function_name,
        "constraints": [],
        "return_type": None,
        "parameters": [],
        "local_variables": [],
        "error": None,
        "mangled_name": None  # V7: Track if we found via demangling
    }
    
    try:
        # Load project with angr
        project = angr.Project(binary_path, auto_load_libs=False)
        
        # Generate CFG (required for decompilation)
        cfg = project.analyses.CFGFast(normalize=True, data_references=True)
        
        # Find the target function (V7: with C++ demangling support)
        func = find_function_by_name(project, cfg, function_name)
        
        if func is None:
            # Provide helpful error message with available functions
            available = list_available_functions(project, cfg)
            func_names = [f.get("demangled", f.get("name", "?")) for f in available[:10]]
            result["error"] = f"Function '{function_name}' not found. Available: {func_names}"
            return result
        
        # Track if we found via mangled name
        if func.name != function_name:
            result["mangled_name"] = func.name
        
        # Run decompiler (which invokes Typehoon internally)
        try:
            dec = project.analyses.Decompiler(func, cfg=cfg.model)
        except Exception as e:
            result["error"] = f"Decompilation failed: {str(e)}"
            return result
        
        # Extract Typehoon results if available
        if dec.clinic and hasattr(dec.clinic, 'typehoon') and dec.clinic.typehoon:
            typehoon = dec.clinic.typehoon
            
            # Extract constraints
            if hasattr(typehoon, '_constraints') and typehoon._constraints:
                for constraint in typehoon._constraints:
                    result["constraints"].append(str(constraint))
            
            # Extract variable types from the solution
            if hasattr(typehoon, 'simtypes_solution') and typehoon.simtypes_solution:
                for var, simtype in typehoon.simtypes_solution.items():
                    constraint = TypehoonConstraint(
                        variable_name=str(var),
                        variable_type=str(simtype),
                        source="local",
                        confidence="high"
                    )
                    result["local_variables"].append(asdict(constraint))
        
        # Extract function prototype from knowledge base
        if func.prototype:
            # Return type
            if func.prototype.returnty:
                result["return_type"] = {
                    "type": str(func.prototype.returnty),
                    "size": getattr(func.prototype.returnty, 'size', None)
                }
            
            # Parameters
            if func.prototype.args:
                for i, arg in enumerate(func.prototype.args):
                    param = {
                        "index": i,
                        "name": arg.name if hasattr(arg, 'name') and arg.name else f"arg{i}",
                        "type": str(arg),
                        "size": getattr(arg, 'size', None)
                    }
                    result["parameters"].append(param)
        
        # Also try to extract from calling convention
        if func.calling_convention:
            cc = func.calling_convention
            if hasattr(cc, 'return_val') and cc.return_val:
                if result["return_type"] is None:
                    result["return_type"] = {
                        "type": str(cc.return_val),
                        "source": "calling_convention"
                    }
        
        result["success"] = True
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def format_typehoon_for_prompt(constraints: Dict) -> str:
    """
    Format Typehoon constraints for inclusion in LLM prompts.
    
    Args:
        constraints: Dict from extract_typehoon_constraints
    
    Returns:
        Formatted string for LLM prompt
    """
    if not constraints.get("success"):
        return ""
    
    lines = []
    lines.append("Inferred Type Information (via Typehoon analysis):")
    
    # Return type
    if constraints.get("return_type"):
        rt = constraints["return_type"]
        lines.append(f"  Return Type: {rt.get('type', 'unknown')}")
    
    # Parameters
    if constraints.get("parameters"):
        lines.append("  Parameters:")
        for p in constraints["parameters"]:
            lines.append(f"    - {p.get('name', '?')}: {p.get('type', 'unknown')}")
    
    # Local variables (limit to most important ones)
    if constraints.get("local_variables"):
        lines.append("  Local Variables:")
        for var in constraints["local_variables"][:10]:  # Limit to 10
            lines.append(f"    - {var.get('variable_name', '?')}: {var.get('variable_type', 'unknown')}")
    
    return "\n".join(lines)


def compare_typeforge_typehoon(
    typeforge_constraints: Dict,
    typehoon_constraints: Dict
) -> Dict:
    """
    Compare TypeForge and Typehoon outputs to identify:
    1. Agreements (high confidence)
    2. Conflicts (need human/LLM resolution)
    3. TypeForge-only (detailed struct info)
    4. Typehoon-only (fallback types)
    
    Args:
        typeforge_constraints: Output from get_type_constraints (TypeForge)
        typehoon_constraints: Output from extract_typehoon_constraints
    
    Returns:
        Merged/compared constraints dict
    """
    comparison = {
        "agreements": [],
        "conflicts": [],
        "typeforge_only": [],
        "typehoon_only": [],
        "merged_constraints": {}
    }
    
    # If TypeForge has data, it's generally more detailed
    if typeforge_constraints:
        comparison["typeforge_only"].extend(typeforge_constraints)
        # TypeForge is primary
        comparison["merged_constraints"]["primary_source"] = "typeforge"
        comparison["merged_constraints"]["data"] = typeforge_constraints
    
    # If Typehoon has data, add as supplement or fallback
    if typehoon_constraints.get("success"):
        if not typeforge_constraints:
            # No TypeForge data, use Typehoon as primary
            comparison["merged_constraints"]["primary_source"] = "typehoon"
            comparison["merged_constraints"]["data"] = typehoon_constraints
        else:
            # Supplement TypeForge with Typehoon
            comparison["typehoon_only"] = {
                "return_type": typehoon_constraints.get("return_type"),
                "parameters": typehoon_constraints.get("parameters"),
            }
    
    return comparison


def demo_typehoon_extraction():
    """
    Demonstration of Typehoon extraction workflow.
    This can be run standalone to test Typehoon functionality.
    """
    import tempfile
    import subprocess
    
    # Create a simple test program
    test_code = """
    #include <stdio.h>
    
    // Simple function with various types
    int func0(int* arr, int size) {
        int sum = 0;
        for (int i = 0; i < size; i++) {
            sum += arr[i];
        }
        return sum;
    }
    
    int main() {
        int arr[] = {1, 2, 3, 4, 5};
        int result = func0(arr, 5);
        printf("Sum: %d\\n", result);
        return 0;
    }
    """
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write source
        src_path = Path(tmpdir) / "test.c"
        bin_path = Path(tmpdir) / "test"
        
        src_path.write_text(test_code)
        
        # Compile
        result = subprocess.run(
            ["gcc", "-O0", "-g", "-o", str(bin_path), str(src_path)],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"Compilation failed: {result.stderr}")
            return None
        
        print(f"Compiled test binary: {bin_path}")
        
        # Extract types using Typehoon
        constraints = extract_typehoon_constraints(str(bin_path), "func0")
        
        print("\n" + "="*60)
        print("Typehoon Analysis Results")
        print("="*60)
        print(json.dumps(constraints, indent=2, default=str))
        
        print("\n" + "="*60)
        print("Formatted for LLM Prompt")
        print("="*60)
        print(format_typehoon_for_prompt(constraints))
        
        return constraints


if __name__ == "__main__":
    print("Typehoon POC - Type Constraint Extraction")
    print("="*60)
    print()
    
    # Check if angr is available
    try:
        import angr
        print(f"✓ angr version: {angr.__version__}")
    except ImportError:
        print("✗ angr not available. Install with: pip install angr")
        exit(1)
    
    # Run demo
    demo_typehoon_extraction()
