"""
Typehoon Type Constraint Extraction Utility for VERITAS Demo

This module provides functionality to extract type constraints from a binary
using angr's Typehoon type analysis system.

Typehoon is a fallback when TypeForge data is unavailable.
It provides:
- Return type inference
- Parameter type inference
- Local variable type inference

Reference: v8-GemTypesandVEX/VERITAS/utils/typehoon_poc.py
"""

from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# Try to import angr (may not be available in all environments)
try:
    import angr
    HAS_ANGR = True
except ImportError:
    HAS_ANGR = False
    print("[Typehoon] Warning: angr not installed. Typehoon analysis unavailable.")

# Try to import cxxfilt for C++ name demangling
try:
    import cxxfilt
    HAS_CXXFILT = True
except ImportError:
    HAS_CXXFILT = False


def is_cpp_mangled_name(name: str) -> bool:
    """Check if a name appears to be a C++ mangled name."""
    if not name:
        return False
    return name.startswith('_Z') or name.startswith('__Z')


def demangle_cpp_name(name: str) -> str:
    """Demangle a C++ mangled name to get the base function name."""
    if not HAS_CXXFILT:
        return name
    if not is_cpp_mangled_name(name):
        return name
    try:
        demangled = cxxfilt.demangle(name)
        # Extract just the function name without parameters
        if '(' in demangled:
            demangled = demangled.split('(')[0]
        demangled = demangled.replace('::', '_')
        return demangled
    except:
        return name


def find_function_by_name(project, cfg, func_name: str):
    """
    Find a function in the binary, handling C++ name mangling.
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
        
        if is_cpp_mangled_name(f.name):
            demangled = demangle_cpp_name(f.name)
            if demangled == func_name or demangled.endswith(func_name):
                return f
        
        if f.name.endswith(func_name):
            return f
    
    # Strategy 4: Search symbol table with demangling
    for sym in project.loader.symbols:
        if not sym.name or not sym.is_function:
            continue
        
        if sym.name == func_name:
            if sym.rebased_addr in cfg.functions:
                return cfg.functions[sym.rebased_addr]
        
        if is_cpp_mangled_name(sym.name):
            demangled = demangle_cpp_name(sym.name)
            if demangled == func_name or demangled.endswith(func_name):
                if sym.rebased_addr in cfg.functions:
                    return cfg.functions[sym.rebased_addr]
    
    return None


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
        "mangled_name": None
    }
    
    if not HAS_ANGR:
        result["error"] = "angr not installed"
        return result
    
    try:
        # Load project with angr
        project = angr.Project(binary_path, auto_load_libs=False)
        
        # Generate CFG (required for decompilation)
        cfg = project.analyses.CFGFast(normalize=True, data_references=True)
        
        # Find the target function
        func = find_function_by_name(project, cfg, function_name)
        
        if func is None:
            result["error"] = f"Function '{function_name}' not found"
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


def format_typehoon_for_prompt(constraints: Dict, max_chars: int = 3000) -> str:
    """
    Format Typehoon constraints for inclusion in LLM prompts.
    
    Args:
        constraints: Dict from extract_typehoon_constraints
        max_chars: Maximum characters to include
        
    Returns:
        Formatted string for LLM prompt
    """
    if not constraints or not constraints.get("success"):
        return ""
    
    lines = []
    lines.append("TYPE CONSTRAINTS (from Typehoon analysis):")
    lines.append("These types were inferred from binary analysis and should guide your implementation.")
    lines.append("⚠️ WARNING: These may be wrong! ASM is your ultimate source of truth.")
    
    func_name = constraints.get('function_name', 'func0')
    lines.append(f"\nFunction: {func_name}")
    
    if constraints.get("mangled_name"):
        lines.append(f"  (C++ mangled: {constraints['mangled_name']})")
    
    # Return type - with warning if void
    ret_type = constraints.get('return_type')
    if ret_type:
        ret_type_str = ret_type.get('type', 'unknown')
        lines.append(f"  Return Type: {ret_type_str}")
        
        if ret_type_str and ret_type_str.lower() == 'void':
            lines.append("  ⚠️ WARNING: TypeHoon says 'void' but this MAY BE WRONG!")
            lines.append("  ⚠️ CHECK ASSEMBLY: If xmm0/eax has value before RET → NOT void!")
            lines.append("  ⚠️ CHECK SEMANTICS: If function COMPUTES a value → it MUST return it!")
    
    # Parameters
    params = constraints.get('parameters', [])
    if params:
        lines.append("  Parameters:")
        for param in params:
            name = param.get('name', 'unknown')
            param_type = param.get('type', 'unknown')
            lines.append(f"    - {name}: {param_type}")
    
    # Local variables
    local_vars = constraints.get('local_variables', [])
    if local_vars:
        lines.append("  Local Variables:")
        for i, var in enumerate(local_vars[:15]):  # Limit to 15
            name = var.get('variable_name', 'unknown')
            var_type = var.get('variable_type', 'unknown')
            lines.append(f"    - {name}: {var_type}")
        if len(local_vars) > 15:
            lines.append(f"    ... ({len(local_vars) - 15} more)")
    
    result = "\n".join(lines)
    if len(result) > max_chars:
        result = result[:max_chars] + "\n... (type constraints truncated)"
    
    return result
