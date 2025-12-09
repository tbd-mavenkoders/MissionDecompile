import yaml
from pathlib import Path
from ..utils.llm_interface import create_llm_interface
from ..utils.compile import Compiler,OptimizationLevel
from ..utils.ghidra import Ghidra
import re
import shutil
import tempfile
import os
from typing import Tuple, List, Dict
import json
from .sort_callgraph import build_call_graph, topological_sort
from ..utils.c_program_parser import create_ghidra_dict
from ..utils.disassembler import Disassembler
from .code_repair import get_optimized_code




# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)
    
    
c = Compiler()
g = Ghidra()
d = Disassembler()
llm_interface = create_llm_interface(
  provider=config["llm"]["gemini_provider"],
  model_name=config["llm"]["gemini_model_name"],
  api_key=config["llm"]["gemini_api_key"]
)

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

def create_cfg_output_dir(executable_name: str) -> Path:
    output_dir = Path(config["paths"]["output_path"]) / "SOG" / executable_name
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir

def get_asm_list(executable_path: Path) -> List:
    status, asm_code = d.disassemble_binary(executable_path, output_dir_path=None)
    if not status:
        print(f"Disassembly failed for {executable_path.name}")
        return {}
    asm_dict = d.function_extraction(asm_code)
    return asm_dict
    
    
  
def split_enrichment(executable_path: Path):
    program_data = {}
    program_data['executable_name'] = executable_path.stem
    program_data['functions'] = []
    
    executable_name = executable_path.stem
    
    # -- Acquire ASM and create a dictionary of function_name -> asm
    asm_dict = {f.name: f.instructions for f in get_asm_list(executable_path)}
    
    # -- Acquire Ghidra Pseudocode and create a dictionary of function_name -> code
    status, code = g.convert_executable_to_ghidra(executable_path,output_dir=None)
    if not status:
        print(f"Ghidra conversion failed for {executable_name}")
        return
    ghidra_dict = create_ghidra_dict(code)
    
    
    # -- Acquire SOG and Call Graph    
    output_dir = create_cfg_output_dir(executable_name)
    cfg_map = g.extract_cfg(executable_path, output_dir)
    callgraph_map = g.extract_call_graph(executable_path, output_dir)
    
    # -- Topologically Sort Call Graph
    callgraph_path = callgraph_map.get('call_graph')
    if not callgraph_path:
        print(f"Call graph extraction failed for {executable_name}")
        return
    callgraph = build_call_graph(callgraph_path)
    sorted_functions = topological_sort(callgraph)
    
    # -- For each function in topological order, enrich its SOG using LLM
    functions = []
    for function_name in sorted_functions:
        f_data = {}
        f_data['f_name'] = function_name
        f_data['asm'] = asm_dict.get(function_name, "")
        f_data['ghidra_code'] = ghidra_dict.get(function_name, "")
        
        # parse the CFG DOT file to get the SOG
        sog_path = cfg_map.get(function_name)
        with open(sog_path, 'r') as f:
            sog_dot = f.read()
        f_data['sog_dot'] = sog_dot
        
        # Get Caller and Callee Context
        callers = [caller for caller, callees in callgraph.items() if function_name in callees]
        callees = callgraph.get(function_name, [])
        f_data['callers'] = callers
        f_data['callees'] = callees
        functions.append(f_data)
        
        # LLM Guided Enrichment for Summary and Optimized Code
        '''
        f_data['summary'] = gen_summary(callers, callees, f_data['sog_dot'], f_data['ghidra_code'])
        status, optimized_code = get_optimized_code(
            original_c_code=f_data['ghidra_code'],
            summary=f_data['summary'],
            language="c",
            max_iterations=3,
            llm_interface=llm_interface
        )
        f_data['optimized_code'] = optimized_code
        f_data['optimization_status'] = status
        '''
        
    program_data['functions'] = functions
        
    return functions



def gen_summary(caller_context: List, callee_context: List, function_sog: str, function_ghidra: str) -> str:
    summary_prompt = config["prompts"]["summary_prompt"]
    prompt = f"{summary_prompt}\n\nCaller Context: {caller_context}\nCallee Context: {callee_context}\nFunction SOG: {function_sog}\nFunction Ghidra: {function_ghidra}\n"

    # Call the LLM API to generate a summary
    response = llm_interface.generate(prompt)
    return response

    
def main():
    data_dir = Path(config["paths"]["test_path"])
    test_executable = data_dir / "test_3"
    data = split_enrichment(test_executable)
    with open(str(Path(output_dir) / f"enriched_data_{test_executable.stem}.json"), "w") as f:
        json.dump(data, f, indent=4)

if __name__ == "__main__":
    main()