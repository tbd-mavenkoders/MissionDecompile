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
  
def get_call_graph_path(executable_name: str) -> Path:
    sog_dir = get_sog_dir(executable_name)
    return sog_dir / "call_graph.dot"
  
def get_topsort(call_graph_path: Path) -> List[str]:
    call_graph = build_call_graph(call_graph_path)
    sorted_functions = topological_sort(call_graph)
    return sorted_functions
  
  
'''
JSON Format for Storing Entire Function
{
  f_name: str,
  sog: Dict
  asm: str
  ghidra_pseudo: str
  summary: str
  optimization_level: OptimizationLevel
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

    
    
  
  
  

  
  