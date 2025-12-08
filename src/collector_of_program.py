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
from sort_callgraph import build_call_graph, topological_sort


c = Compiler()


# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
print(f"Loading config from: {CONFIG_PATH}")
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

output_dir = Path(config["paths"]["output_path"])

def get_sog_dir(executable_name: str) -> Path:
    return output_dir / "SOG" / executable_name
  
def get_sog_json(executable_name: str, function_name: str) -> Path:
    sog_dir = get_sog_dir(executable_name)
    return sog_dir / f"{function_name}.json"
  
'''
JSON Format for Storing Entire Function
{
  f_name: str,
  sog: {
    "blocks": [
      {
        "id": str,
        "instructions": [
          {
            "address": str,
            "mnemonic": str,
            "operands": List[str]
          }
        ]
      }
    ],
    "edges": [
      {
        "src": str,
        "dst": str,
        "type": str
      }
    ]
    "entry": str
    "function_name": str
  }
  ghidra_pseudo: str
  summary: str
  optimization_status: bool
  optimized_code: str
}
 
TODO:
0.0 - Acquire Topological Sort of the Call Graph
0.1 - For each function in the call graph: 
  1.1 - Obtain Ghidra Pseudocode of the function 
  1.2 - Summarize the function using LLM
  1.3 - Generate Optimized Code using LLM
0.4 - Combine all into a single JSON structure
0.5 - Run Static Repair on the optimized program
'''

def enrich_function_data(executable_path: str, function_name: str):
  executable_name = Path(executable_path).name
  function_data = {}
  
  # Load SOG JSON
  sog_json_path = get_sog_json(executable_name, function_name)
  with open(sog_json_path, "r") as fp:
    sog_data = json.load(fp)
    
  # Load Ghidra Pseudocode
  g = Ghidra()
  success, ghidra_output = g.convert_executable_to_ghidra(
  
  
  


def combine_into_json(executable_path: str):
  executable_name = Path(executable_path).name
  call_graph_path = get_sog_dir(executable_name) / "call_graph.dot"
  ordered_functions = topological_sort(build_call_graph(call_graph_path))
  
  data = {}
  data["program_name"] = executable_name
  data["top_sort"] = ordered_functions
  data["functions"] = []
  for func_name in ordered_functions:
    enrich_function_data(executable_name, func_name)
    
    
    
    
  
  
  

  
  