import yaml
from pathlib import Path
from ..utils.llm_interface import create_llm_interface, clean_llm_output
from ..utils.compile import Compiler,OptimizationLevel
from ..utils.ghidra import Ghidra
import re
import shutil
import tempfile
import os
from typing import Tuple, List, Dict
import json
import pyghidra


c = Compiler()


# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
print(f"Loading config from: {CONFIG_PATH}")
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

corpus_path = Path(config["paths"]["test_path"])
output_path = Path(config["paths"]["output_path"])
  
  


def main():
  g = Ghidra()
  #g.extract_cfg(executable_path=corpus_path/"test_3", output_dir=output_path/ "SOG")
  g.extract_call_graph(executable_path=corpus_path/"test_3", output_dir=output_path/ "SOG")
  
  
  
if __name__ == "__main__":
  main()