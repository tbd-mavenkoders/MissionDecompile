"""
TypeForge Type Constraint Acquisition Utility for VERITAS Demo

This module provides functionality to run TypeForge (Ghidra-based) type analysis
on a single executable binary to extract type constraints.

Reference: v4-TypeForge/MissionDecompile/evaluator/mbpp_exes.py
"""

import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Dict
import json


def acquire_typeforge_constraints(
    exec_path: Path,
    ghidra_path: Path,
    output_dir: Path,
    timeout: int = 300
) -> Optional[Dict]:
    """
    Run TypeForge analysis on a single executable to extract type constraints.
    
    TypeForge is a Ghidra postscript that extracts:
    - Parameter types and names
    - Local variable types  
    - Struct layouts with field offsets
    - Pointer vs array disambiguation
    - Signed vs unsigned integer types
    
    Args:
        exec_path: Path to the executable binary
        ghidra_path: Path to Ghidra installation root (e.g., ghidra_11.0.3_PUBLIC)
        output_dir: Directory to store TypeForge output
        timeout: Timeout in seconds for TypeForge analysis
        
    Returns:
        Dict containing type constraints or None if analysis failed
    """
    if not exec_path.exists():
        print(f"[TypeForge] Error: Executable not found: {exec_path}")
        return None
        
    ghidra_headless = ghidra_path / "support" / "analyzeHeadless"
    if not ghidra_headless.exists():
        print(f"[TypeForge] Error: Ghidra headless not found: {ghidra_headless}")
        return None
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create a temporary project directory
    with tempfile.TemporaryDirectory() as temp_project_dir:
        command = [
            str(ghidra_headless),
            temp_project_dir,
            "TypeForgeProject",
            "-deleteProject",
            "-import",
            str(exec_path),
            "-postScript",
            "TypeForge.java",
            f"output={str(output_dir)}"
        ]
        
        try:
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            
            if result.returncode != 0:
                print(f"[TypeForge] Analysis failed for {exec_path.name}")
                print(f"[TypeForge] stderr: {result.stderr[:500]}")
                return None
            
            print(f"[TypeForge] Analysis completed for {exec_path.name}")
            
            # Load the constraints from output
            return load_typeforge_constraints(output_dir, "func0")
            
        except subprocess.TimeoutExpired:
            print(f"[TypeForge] Analysis timed out for {exec_path.name}")
            return None
        except Exception as e:
            print(f"[TypeForge] Error running analysis: {e}")
            return None


def load_typeforge_constraints(typeforge_path: Path, function_name: str = "func0") -> Optional[Dict]:
    """
    Load TypeForge constraints from the output directory.
    
    Args:
        typeforge_path: Path to TypeForge output directory
        function_name: Name of the function to extract constraints for
        
    Returns:
        Dict with type constraints or None if not available
    """
    if not typeforge_path.exists():
        return None
    
    # Check if there are constraint files
    type_files = list(typeforge_path.glob("*.json"))
    if not type_files:
        return None
    
    # Read the main varType.json file
    varType_file = typeforge_path / "varType.json"
    all_constraints = []
    
    if varType_file.exists():
        try:
            with open(varType_file, "r") as f:
                varType = json.load(f)
            
            # Select only constraints pertaining to the target function
            for type_constraint in varType.values():
                if type_constraint.get('Name') != function_name:
                    continue
                
                # Process local variables
                local_variables = type_constraint.get('LocalVariables', {})
                for var_loc, var_info in local_variables.items():
                    if 'TypeConstraint' in var_info:
                        file_name = var_info['TypeConstraint']
                        # Try both _final.json and _final_DI.json variants
                        constraint_file = typeforge_path / f"{file_name}_final.json"
                        constraint_file_dl = typeforge_path / f"{file_name}_final_DI.json"
                        
                        if constraint_file.exists():
                            with open(constraint_file, "r") as cf:
                                constraint_data = json.load(cf)
                            var_info['TypeConstraint'] = constraint_data
                        elif constraint_file_dl.exists():
                            with open(constraint_file_dl, "r") as cf:
                                constraint_data = json.load(cf)
                            var_info['TypeConstraint'] = constraint_data
                
                # Process parameters
                parameters = type_constraint.get('Parameters', {})
                for param_loc, param_info in parameters.items():
                    if 'TypeConstraint' in param_info:
                        file_name = param_info['TypeConstraint']
                        constraint_file = typeforge_path / f"{file_name}.json"
                        if constraint_file.exists():
                            with open(constraint_file, "r") as cf:
                                constraint_data = json.load(cf)
                            param_info['TypeConstraint'] = constraint_data
                
                all_constraints.append(type_constraint)
                
        except Exception as e:
            print(f"[TypeForge] Error loading constraints: {e}")
            return None
    
    return all_constraints if all_constraints else None


def format_typeforge_for_prompt(type_constraints: Dict, max_chars: int = 3000) -> str:
    """
    Format TypeForge constraints into a readable string for LLM prompts.
    
    Args:
        type_constraints: Dict from load_typeforge_constraints()
        max_chars: Maximum characters to include
        
    Returns:
        Formatted string describing the type constraints
    """
    if not type_constraints:
        return ""
    
    lines = []
    lines.append("TYPE CONSTRAINTS (from TypeForge analysis):")
    lines.append("These types were inferred from binary analysis and should guide your implementation:")
    
    for constraint in type_constraints:
        func_name = constraint.get('Name', 'unknown')
        lines.append(f"\nFunction: {func_name}")
        
        # Parameters
        params = constraint.get('Parameters', {})
        if params:
            lines.append("  Parameters:")
            for param_loc, param_info in params.items():
                name = param_info.get('Name', 'unknown')
                desc = param_info.get('desc', '')
                type_detail = param_info.get('TypeConstraint', {})
                if isinstance(type_detail, dict):
                    type_str = type_detail.get('type', desc)
                else:
                    type_str = desc
                lines.append(f"    - {name}: {type_str}")
        
        # Local variables (limit to most important)
        local_vars = constraint.get('LocalVariables', {})
        if local_vars:
            lines.append("  Local Variables:")
            count = 0
            for var_loc, var_info in local_vars.items():
                if count >= 15:  # Limit to 15 variables
                    lines.append(f"    ... ({len(local_vars) - 15} more)")
                    break
                name = var_info.get('Name', 'unknown')
                desc = var_info.get('desc', '')
                type_detail = var_info.get('TypeConstraint', {})
                if isinstance(type_detail, dict):
                    type_str = type_detail.get('type', desc)
                else:
                    type_str = desc
                lines.append(f"    - {name}: {type_str}")
                count += 1
    
    result = "\n".join(lines)
    
    # Truncate if too long
    if len(result) > max_chars:
        result = result[:max_chars] + "\n... (type constraints truncated)"
    
    return result
