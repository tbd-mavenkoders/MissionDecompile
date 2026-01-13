import re
import subprocess
import shutil
from pathlib import Path
from typing import List, Optional, Tuple, Dict
from dataclasses import dataclass
from .logger import setup_logger
import argparse



@dataclass
class AssemblyFunction:
  name: str
  address: str
  instructions: List[str]



class Disassembler:
  def __init__(self,objdump_path: str = "objdump", log_dir: Optional[str] = None):
    self.objdump_path = objdump_path
    self.logger = setup_logger("Disassembler", log_dir)
    
    # Ensure objdump is accessible
    self.verify_objdump(objdump_path)
    
    # Patterns used to parse objdump -d output
    # Example function header: 401130 <function_name>:
    self.function_pattern = re.compile(r'^\s*([0-9a-fA-F]+)\s+<([^>]+)>:')
    # Example instruction:  401130: 48 83 ec 08    sub    rsp,0x8
    self.instruction_pattern = re.compile(r'^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F\s]+)\s+(.+)$')
    # Example comment : 401130: 48 83 ec 08    sub    rsp,0x8    # adjust stack
    self.comment_pattern = re.compile(r'#.*$')
    
  def verify_objdump(self,objdump_path: str):
    """
    Verify if objdump is accessible
    Args:
        objdump_path: Path to the objdump executable
    Raises:
        DisassemblyError: If objdump is not accessible
        
    """
    command = [objdump_path, "--version"]
    try:
      result = subprocess.run(command,capture_output=True, check=True,timeout=10)
      if result.returncode == 0:
        self.logger.info(f"Objdump {objdump_path} is accessible.")
      else:
        raise DisassemblyError(f"Objdump {objdump_path} is not accessible.")
    except (subprocess.TimeoutExpired,FileNotFoundError) as e:
      raise DisassemblyError(f"Objdump {objdump_path} is not accessible: {str(e)}")
  def disassemble_binary(
    self,
    binary_dir_path: str,
    output_dir_path: str,
    intel_syntax: bool = True,
    demangle: bool = True
              ) -> Tuple[bool, str]:
    """
    Disassembles Binary using objdump -d and writes output to specified directory.
    Args:
        binary_dir_path: Path to the binary file
        output_dir_path: Path to the output directory
        intel_syntax: Use Intel syntax if True, else AT&T syntax
        demangle: Demangle C++ symbols if True
    Returns (success, stdout_or_error).
    """
    binary_path = Path(binary_dir_path)
    if not binary_path.exists():
      msg = f"Binary not found: {binary_path}"
      self.logger.error(msg)
      return False, msg
    
    # Run objdump command
    command = ['objdump', '-d']
    if intel_syntax:
      command += ['-M', 'intel']
    if demangle:
      command += ['-C']
    command += [str(binary_path)]
    
    try:
      result = subprocess.run(command,capture_output=True,text=True,timeout=60)
      if result.returncode == 0:
        success_msg = f"Disassembly successful for {binary_path}"
        self.logger.info(success_msg)
        return True, result.stdout
      else:
        error_msg = f"Disassembly failed for {binary_path}: {result.stderr.strip()}"
        self.logger.error(error_msg)
        return False, error_msg
    except Exception as e:
      error_msg = f"Disassembly error for {binary_path}: {str(e)}"
      self.logger.error(error_msg)
      return False, error_msg
    
  def clean_assembly(self,assembly_text: str) -> str:
    """
    Cleans the disassembled assembly text by removing addresses, hex bytes, and comments.
    Keeps function headers for further processing.
    Args:
        assembly_text: Raw disassembled assembly text
    Returns:
        Cleaned assembly text
    """
    output_asm: List[str] = []
    for line in assembly_text.splitlines():
      if not line.strip():
        continue
      
      # Check for function header
      func_match = self.function_pattern.match(line)
      if func_match:
        addr, name = func_match.groups()
        output_asm.append(f"{addr} <{name}>:")
        continue
      
      # Check for instruction line
      inst_match = self.instruction_pattern.match(line)
      if inst_match:
        _, _, instr = inst_match.groups()
        # Remove comments
        instr = self.comment_pattern.sub('', instr).strip()
        if instr:
          output_asm.append(instr)
        continue
      
    return '\n'.join(output_asm)
      
  def function_extraction(self,assembly_text: str) -> Dict[str, str]:
    """
    Extracts functions from cleaned assembly text.
    Args:
        assembly_text: Cleaned assembly text
    Returns:
        Dictionary mapping function names to their assembly code
    """
    functions: List[AssemblyFunction] = []
    current_function: Optional[AssemblyFunction] = None
    
    for line in assembly_text.splitlines():
      func_match = self.function_pattern.match(line)
      # if line matches function name
      if func_match:
        addr, name = func_match.groups()
        # If there's a current function being processed, save it
        if current_function:
          functions.append(current_function)
        current_function = AssemblyFunction(name=name,address=addr,instructions=[])
        continue
      
      if current_function is None:
        continue
      
      instruction_match = self.instruction_pattern.match(line)
      # if matches with instruction
      if instruction_match:
        _, _, instr = instruction_match.groups()
        instr = self.comment_pattern.sub('', instr).strip()
        if instr:
          current_function.instructions.append(instr)
          
    if current_function:
      functions.append(current_function)
      
    self.logger.info(f"Extracted {len(functions)} functions from assembly.")
    return functions
  
  def format_for_llm(self,assembly_text: str) -> str:
    """
    Formats cleaned assembly text for LLM input.
    Args:
        assembly_text: Cleaned assembly text
    Returns:
        Formatted assembly text suitable for LLM input  
    """
    cleaned_asm = self.clean_assembly(assembly_text)
    functions_asm = self.function_extraction(assembly_text)
    
    output: List[str] = []
    for f in functions_asm:
      output.append(f"<FUNC> {f.name} at {f.address}")
      output.extend(f.instructions)
      output.append("<END_FUNC>\n")
      output.append("")

    self.logger.info(f"Formatted {len(functions_asm)} functions for LLM input.")

    return '\n'.join(output)
  
  def disassemble_custom(
    self,
    binary_path: str,
    output_dir: str,
    save_raw: bool = True,
    save_cleaned: bool = True,
    save_formatted: bool = True
                      ) -> Dict[str, str]:
    """
    Disassembles a binary and processes the output.
    Args:
        binary_path: Path to the binary file
        output_dir: Directory to save outputs
        save_raw: Save raw disassembly if True
        save_cleaned: Save cleaned assembly if True
        save_formatted: Save formatted assembly for LLM if True
    Returns:
        Dictionary with keys 'raw', 'cleaned', 'formatted' based on saved outputs
    """
    outputs: Dict[str, str] = {}
    binary_path = Path(binary_path)
    output_dir = Path(output_dir)
    # Delete output_dir if already exists
    if output_dir.exists():
      shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    file_name = binary_path.stem
    
      
    success, disassembly_output = self.disassemble_binary(binary_path, output_dir)
    if not success:
      self.logger.error(f"Failed to disassemble {binary_path}")
      return outputs
    
    if save_raw:
      raw_path = output_dir / f"{file_name}_raw.asm"
      raw_path.write_text(disassembly_output)
      outputs['raw'] = str(raw_path)
      
    if save_cleaned:
      cleaned_asm = self.clean_assembly(disassembly_output)
      cleaned_path = output_dir / f"{file_name}_cleaned.asm"
      cleaned_path.write_text(cleaned_asm)
      outputs['cleaned'] = str(cleaned_path)
      
    if save_formatted:
      formatted_asm = self.format_for_llm(disassembly_output)
      formatted_path = output_dir / f"{file_name}_formatted.asm"
      formatted_path.write_text(formatted_asm)
      outputs['formatted'] = str(formatted_path)

    self.logger.info(f"Disassembled {binary_path} and saved outputs to {output_dir}")

    return outputs
  
  def disassemble_binary_directory(
    self,
    binary_dir: str,
    output_dir: str,
    recursive: bool = True
  )->Dict[str, Dict[str, str]]:
    """
    Disassembles all binaries in a directory and processes them.
    Args:
        binary_dir: Directory containing binaries
        output_dir: Directory to save outputs
        recursive: If True, process directories recursively
    Returns:
        Dictionary mapping binary paths to their processed outputs
    """
    binary_dir_path = Path(binary_dir)
    results: Dict[str, Dict[str, str]] = {}
    
    if recursive:
      candidates = [p for p in binary_dir_path.rglob('*') if p.is_file() and not p.suffix and p.exists()]
    else:
      candidates = [p for p in binary_dir_path.glob('*') if p.is_file() and not p.suffix and p.exists()]
    
    self.logger.info(f"Found {len(candidates)} candidate binaries in {binary_dir}")
    
    for binary_path in candidates:
      rel_path = binary_path.relative_to(binary_dir_path)
      out_subdir = Path(output_dir) / rel_path.parent
      out_subdir.mkdir(parents=True, exist_ok=True)
      res = self.disassemble_custom(str(binary_path), str(out_subdir))
      if res:
        results[str(binary_path)] = res
    
    self.logger.info(f"Processed {len(results)}/{len(candidates)} binaries")
    return results

  
  
  
      
    
        
    
    
  
      
    
      
  