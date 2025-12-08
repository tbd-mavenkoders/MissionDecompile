import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple, Dict
from enum import Enum
import argparse
import shutil
import yaml


# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
print(f"Loading config from: {CONFIG_PATH}")

with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)
    


class Ghidra:
  def __init__(self, ghidra_path: str = config["paths"]["ghidra_path"], post_script: str = config["paths"]["postscript_path"]):
    self.ghidra_path = ghidra_path
    self.post_script = post_script

  def convert_executable_to_ghidra(self, executable_path: str, output_dir: str) -> Tuple[bool, str]:
    """
    Convert an executable binary to Ghidra decompiled pseudo C code.
    Args:
      executable_path: Path to the executable binary
      output_dir: Directory to save the decompiled output
    Returns:
      Tuple[success, output_path_or_error_message]
    """
    print(f"Starting Ghidra decompilation for {executable_path}")
    executable_path = Path(executable_path)

    if not executable_path.exists():
      msg = f"Executable not found: {executable_path}"
      return False, msg

    with tempfile.TemporaryDirectory() as temp_dir:
      output_file = Path(temp_dir) / f"{executable_path.stem}_decompiled.c"
      command = [
        self.ghidra_path,
        temp_dir,
        "tmp_ghidra_proj",
        "-import",
        str(executable_path),
        "-postScript",
        self.post_script,
        str(output_file),
        "-deleteProject",
      ]
      try:
        subprocess.run(command, text=True, capture_output=True, check=True, timeout=120)
        print(f"Ghidra decompilation succeeded for {executable_path.name}")
        with open(output_file, 'r') as f:
          enriched_code = f.read()
        return True, enriched_code
      except Exception as e:
        print(f"Ghidra decompilation failed: {e}")
        return False, str(e)


  def extract_cfg(self, executable_path: str, output_dir: str, timeout:int=180) -> Dict[str, str]:
    """
    Extract per-function CFGs from `executable_path` using Ghidra headless and return a mapping
    function_safe_name -> path_to_dot_file.

    Args:
      executable_path: path to binary
      output_dir: directory to store DOT files
      timeout: seconds to allow for the headless run

    Returns:
      dict mapping safe function name to absolute DOT file path. On error, raises RuntimeError.
    """
    executable_path = Path(executable_path)
    output_dir = Path(output_dir)
    if not executable_path.exists():
      raise FileNotFoundError(f"Executable not found: {executable_path}")
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as temp_dir:
      script_path = Path(config["paths"]["scripts_path"]) / 'cfg_extractor.py'

      # Build ghidraHeadless command
      command = [
        self.ghidra_path,
        temp_dir,
        'tmp_ghidra_proj',
        '-import', str(executable_path),
        '-scriptPath', str(script_path.parent),
        '-postScript', str(script_path), str(output_dir),
        '-deleteProject',
      ]
      try:
        result = subprocess.run(command, text=True, capture_output=True, check=True, timeout=timeout)
        print(result.stdout)
        print(result.stderr)

      except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Ghidra headless failed: {e.stderr}\n{e.stdout}")
      except Exception as e:
        raise RuntimeError(str(e))

    # collect dot files
    results: Dict[str,str] = {}
    for p in output_dir.rglob('*.dot'):
      results[p.stem] = str(p.resolve())
    return results
  
  def extract_call_graph(self, executable_path: str, output_dir: str, timeout:int=180) -> Dict[str, str]:
    """
    Extract the overall call graph from `executable_path` using Ghidra headless and return a mapping
    function_name -> path_to_dot_file.

    Args:
      executable_path: path to binary
      output_dir: directory to store DOT file
      timeout: seconds to allow for the headless run
    Returns:
      dict mapping 'call_graph' to absolute DOT file path. On error, raises RuntimeError.
    """
    executable_path = Path(executable_path)
    output_dir = Path(output_dir)
    if not executable_path.exists():
      raise FileNotFoundError(f"Executable not found: {executable_path}")
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as temp_dir:
      script_path = Path(config["paths"]["scripts_path"]) / 'call_graph.py'

      # Build ghidraHeadless command
      command = [
        self.ghidra_path,
        temp_dir,
        'tmp_ghidra_proj',
        '-import', str(executable_path),
        '-scriptPath', str(script_path.parent),
        '-postScript', str(script_path), str(output_dir),
        '-deleteProject',
      ]
      try:
        result = subprocess.run(command, text=True, capture_output=True, check=True, timeout=timeout)
        print(result.stdout)
        print(result.stderr)

      except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Ghidra headless failed: {e.stderr}\n{e.stdout}")
      except Exception as e:
        raise RuntimeError(str(e))

    # collect dot files
    results: Dict[str,str] = {}
    for p in output_dir.rglob('*.dot'):
      results[p.stem] = str(p.resolve())
    return results

    


  

