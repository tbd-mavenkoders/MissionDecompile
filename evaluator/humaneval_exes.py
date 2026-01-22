import yaml
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.compile import Compiler, OptimizationLevel
from utils.llm_interface import create_llm_interface
import tempfile
import subprocess
from typing import Tuple, List, Dict, Optional
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import threading
import shutil

c = Compiler()

# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
print(f"Loading config from: {CONFIG_PATH}")

with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

corpus_path = Path(config["humaneval"]["corpus_path"])
output_path = Path(config["humaneval"]["output_path"])
ghidra_path = Path(config["paths"]["ghidra_root_path"])


def process_json_file(json_file: Path):
    with open(json_file, "r") as f:
        dataset = json.load(f)
        
    total = 0
    success = 0
    for data in dataset:
      with tempfile.TemporaryDirectory() as tempdir:
        src_file = Path(tempdir) / f"func_{data['index']}.{data['language']}"
        binary_file = Path(corpus_path) / "executables" / f"func_{data['index']}.exe"
        with open(src_file, "w") as sf:
          sf.write(data["func_dep"])
          sf.write(data["func"])
        
        status, compile_message = c.compile_source(
          source_file_path = src_file,
          output_file_path = binary_file,
          opt = OptimizationLevel[data["opt"]],
          is_cpp = (data["language"] == "cpp"),
          c_flag = True,
          extra_flags = ["-lm"] 
        )
        if not status:
          print(f"Compilation failed for func_{data['index']}: {compile_message}")
        else:
          success += 1
          print(f"Compiled func_{data['index']} successfully to {binary_file}")
      total += 1
        
'''
[GHIDRA_INSTALL_DIR]/support/analyzeHeadless
[PROJECT_DIR] [PROJECT_NAME] 
-deleteProject -import [STRIPPED_BINARY]
 -postScript TypeForge.java output=[OUTPUT_DIR]
 
 Example Command
 /workspace/home/aiclub1/B220032CS_Jaefar/fyp/repos/ansaf/ghidra_11.0.3_PUBLIC/support/analyzeHeadless 
'''
        
def acquire_type_constraints(exec_path: Path):
  ghidra_headless_dir = ghidra_path / "support" / "analyzeHeadless"
  project_dir = corpus_path / "typeforge" / "project"
  output_dir = corpus_path / "typeforge" / exec_path.stem
  command = [
    str(ghidra_headless_dir),
    str(project_dir),
    "TypeForgeProject",
    "-deleteProject",
    "-import",
    str(exec_path),
    "-postScript",
    "TypeForge.java",
    f"output={str(output_dir)}"
  ]
  # wait for result to complete before returning
  try:
    result = subprocess.run(command, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
      print(f"TypeForge analysis failed for {exec_path.name}: {result.stderr}")
      return None
    else:
      print(f"TypeForge analysis completed for {exec_path.name}")
      return output_dir
    
    
    
  except subprocess.TimeoutExpired:
    print(f"TypeForge analysis timed out for {exec_path.name}")
    return None
      
    
      
def process_executables(exec_dir: Path):
  exec_files = list(exec_dir.glob("*.exe"))
  total = 0
  success = 0
  failure = 0
  for exec_file in exec_files:
    output = acquire_type_constraints(exec_file)
    if output is None:
      failure += 1
      print(f"Skipping cleanup for {exec_file.name} due to analysis failure.")
    else:
      success += 1
      print(f"Successfully processed {exec_file.name}")
      
    total += 1
    print(f"Processed {total} executables: {success} success, {failure} failure.")
    project_dir = corpus_path / "typeforge" / "project"
    # delete folder and its contents
    shutil.rmtree(project_dir, ignore_errors=True)
    # create empty folder
    project_dir.mkdir(parents=True, exist_ok=True)
    
    
  
        
def main():
  exec_dir = corpus_path / "executables"
  process_executables(exec_dir)
  
if __name__ == "__main__":
    main()
      
      
    