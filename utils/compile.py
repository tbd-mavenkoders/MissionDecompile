"""
Compiler for C/C++ source files using GCC/G++ with configurable optimization levels.
"""

import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple, Dict
from enum import Enum
from .logger import setup_logger
import argparse
import shutil



class OptimizationLevel(Enum):
  O0 = "-O0"  # No optimization
  O1 = "-O1"  # Basic optimization
  O2 = "-O2"  # Moderate optimization
  O3 = "-O3"  # Aggressive optimization
  
  
  
class Compiler:
  
  def __init__(self, gcc_path: str = "gcc", gpp_path: str = "g++", log_dir: Optional[str] = None):
    self.gcc_path = gcc_path
    self.gpp_path = gpp_path
    self.logger = setup_logger("Compiler", log_dir)
    
    # Ensure GCC and G++ are accessible
    self.verify_compiler(gcc_path)
    self.verify_compiler(gpp_path)
    
  def verify_compiler(self,compiler_path: str):
    """
    Verify if compiler is accessible
    
    Args:
        compiler_path: Path to the compiler executable
    Raises:
        CompilationError: If the compiler is not accessible
        
    """
    command = [compiler_path, "--version"]
    try:
      result = subprocess.run(command,capture_output=True, check=True,timeout=10)
      if result.returncode == 0:
        self.logger.info(f"Compiler {compiler_path} is accessible.")
      else:
        raise CompilationError(f"Compiler {compiler_path} is not accessible.")
      
    except (subprocess.TimeoutExpired,FileNotFoundError) as e:
      raise CompilationError(f"Compiler {compiler_path} is not accessible: {str(e)}")
    
  def compile_source(
    self,
    source_file_path: str,
    output_file_path: str,
    is_cpp: bool,
    opt: OptimizationLevel = OptimizationLevel.O0,
    extra_flags: Optional[List[str]] = None,
    include_dirs: Optional[List[str]] = None,
    library_dirs: Optional[List[str]] = None,
    libraries: Optional[List[str]] = None
              ) -> Tuple[bool, str]:
    """
    Compiles a C/C++ source file into an executable binary.
    
    Args:
        source_file_path: Path to the source file
        output_file_path: Path to the output binary file
        is_cpp: Whether the source file is C++ (True) or C (False)
        optimization_level: Optimization level for compilation
        extra_flags: Additional compiler flags
        include_dirs: List of include directories
        library_dirs: List of library directories
        libraries: List of libraries to link against
    
    """
    
    compiler = self.gpp_path if is_cpp else self.gcc_path
    
    source_path = Path(source_file_path)
    output_path = Path(output_file_path)
    
    # Verify Source Path exists
    if not source_path.exists():
      error_message = f"Source file {source_file_path} does not exist."
      self.logger.error(error_message)
      return False, error_message
    
    # Create Output Directory if not exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    command = [compiler,
               "-c",
               str(source_path),
               "-o", str(output_path), 
               opt.value, 
               "-w"]
    
    # Include directories
    if include_dirs:
      for inc_dir in include_dirs:
        command.extend(["-I", inc_dir])
        
    # Library directories
    if library_dirs:
      for lib_dir in library_dirs:
        command.extend(["-L", lib_dir])
        
    # Libraries
    if libraries:
      for lib in libraries:
        command.extend(["-l", lib])
        
    # Extra flags
    if extra_flags:
      command.extend(extra_flags)

      
    # Execute Compilation
    self.logger.info(f"Compiling {source_file_path} to {output_file_path}")
    
    try:
      result = subprocess.run(command, capture_output=True, text=True, timeout=60)
      
      if result.returncode == 0:
        success_message = f"Compilation succeeded: {output_file_path}"
        os.chmod(output_file_path, 0o777)  # make executable
        #self.logger.info(success_message)
        return True, success_message
      else:
        error_message = f"Compilation failed: {result.stderr}"
        #self.logger.error(error_message)
        return False, error_message
      
    except subprocess.TimeoutExpired:
      error_message = "Compilation timed out."
      #self.logger.error(error_message)
      return False, error_message
    
    except Exception as e:
      error_message = f"Compilation error: {str(e)}"
      #self.logger.error(error_message)
      return False, error_message
    
  def compile_source_with_multiple_optimizations(
    self,
    source_file_path: str,
    output_dir_path: str,
    is_cpp: bool = False,
    opt_list: List[OptimizationLevel] = [OptimizationLevel.O0, OptimizationLevel.O1, OptimizationLevel.O2, OptimizationLevel.O3],
    extra_flags: Optional[List[str]] = None,
    include_dirs: Optional[List[str]] = None,
    library_dirs: Optional[List[str]] = None,
    libraries: Optional[List[str]] = None
              ) -> Dict[OptimizationLevel, Tuple[bool, str]]:
    
    """
    Compiles a single source file using multiple optimization levels.
    
    Args:
        source_file_path: Path to the source file
        output_dir_path: Base path for the output binary files
        is_cpp: Whether the source file is C++ (True) or C (False)
        opt: Optimization level for compilation
        extra_flags: Additional compiler flags
        include_dirs: List of include directories
        library_dirs: List of library directories
        libraries: List of libraries to link against
        
    Returns:
        Dictionary mapping optimization levels to (success, message) tuples
        
    """
    results = {}
    source_path = Path(source_file_path)
    output_dir = Path(output_dir_path)
    
    # Delete and recreate output directory to avoid conflicts
    if output_dir.exists():
      shutil.rmtree(output_dir)
      
      
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for level in opt_list:
      output_name = f"{source_path.stem}_{level.name}"
      output_path = output_dir / output_name
      
      # Execute Compilation
      status, message = self.compile_source(
        source_file_path=str(source_path),
        output_file_path=str(output_path),
        is_cpp=is_cpp,
        opt=level,
        extra_flags=extra_flags,
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        libraries=libraries
      )
      
      results[level] = (status, message, str(output_path))
      
    return results
  
  def compile_directory(
    self,
    source_dir_path: str,
    output_dir_path: str,
    recursive: bool = True,
    is_cpp: bool = False,
    opt: OptimizationLevel = OptimizationLevel.O0,
    extra_flags: Optional[List[str]] = None,
    include_dirs: Optional[List[str]] = None,
    library_dirs: Optional[List[str]] = None,
    libraries: Optional[List[str]] = None
              ) -> Dict[str, Tuple[bool, str]]:
    """
    Compiles all C/C++ source files in a directory.
    
    Args:
        source_dir_path: Path to the source directory
        output_dir_path: Path to the output directory
        is_cpp: Whether the source files are C++ (True) or C (False)
        optimization_level: Optimization level for compilation
        extra_flags: Additional compiler flags
        include_dirs: List of include directories
        library_dirs: List of library directories
        libraries: List of libraries to link against
        
    Returns:
        Dictionary mapping source file names to (success, message) tuples
        
    """
    results = {}
    
    source_path = Path(source_dir_path)
    output_path = Path(output_dir_path)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Define file extensions
    file_extensions = [".c", ".cpp", ".cc", ".cxx", ".c++"]
    
    # Find source files
    if recursive:
        source_files = []
        for ext in file_extensions:
            source_files.extend(source_path.rglob(f"*{ext}"))
    else:
        source_files = []
        for ext in file_extensions:
            source_files.extend(source_path.glob(f"*{ext}"))
  
    self.logger.info(f"Found {len(source_files)} source files in {source_path}")
    
    for source_file in source_files:
      # check C or C++
      is_cpp_file = is_cpp or source_file.suffix in [".cpp", ".cc", ".cxx", ".c++"]
      # preserve directory structure while creating output
      relative_path = source_file.relative_to(source_path)
      output_file_path = output_path / relative_path.parent / source_file.stem
      
      # Execute Compilation
      status, message = self.compile_source(
        source_file_path=str(source_file),
        output_file_path=str(output_file_path),
        is_cpp=is_cpp_file,
        opt=opt,
        extra_flags=extra_flags,
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        libraries=libraries
      )
      
      results[str(source_file)] = (status, message, str(output_file_path))
      
    # Summary of results
    self.logger.info("Compilation Summary:")
    compiled_count = sum(1 for res in results.values() if res[0])
    self.logger.info(f"Successfully compiled {compiled_count} out of {len(results)} files.")
      
    return results
  

  