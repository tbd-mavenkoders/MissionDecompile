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
'''
llm_interface = create_llm_interface(
  provider=config["llm"]["gemini_provider"],
  model_name=config["llm"]["gemini_model_name"],
  api_key=config["llm"]["gemini_api_key"]
)
'''
llm_interface = create_llm_interface(
    provider=config["llm"]["ollama_provider"],
    model_name=config["llm"]["ollama_model_name"],
    # api_key=config["llm"].get("ollama_api_key"),  # Not needed for Ollama
    base_url=config["llm"]["ollama_base_url"]
)


output_dir = Path(config["paths"]["output_path"])


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

def get_ghidra_dict(executable_path: Path) -> Dict[str, str]:
    status, code = g.convert_executable_to_ghidra(executable_path,output_dir=None)
    if not status:
        print(f"Ghidra conversion failed for {executable_path.name}")
        return {}
    ghidra_dict = create_ghidra_dict(code)
    return ghidra_dict

def separate_header_and_source(code: str) -> Tuple[str, str]:
    header = ""
    source = ""
    lines = code.splitlines(keepends=True)
    for line in lines:
        if line.strip().startswith("#include") or line.strip().startswith("typedef") or line.strip().startswith("struct") or line.strip().startswith("enum"):
            header += line
        else:
            source += line
    return header, source

def get_program_code(program_data: Dict) -> Dict:
    program_header = ""
    program_code = ""
    combined_code = ""
    for function in program_data['functions']:
        header, source = separate_header_and_source(function['optimized_code'])
        program_header += header + "\n"
        program_code += source + "\n"
    combined_code = program_header + "\n" + program_code
    
    return combined_code
  
    
  
def split_enrichment(executable_path: Path):
    program_data = {}
    program_data['executable_name'] = executable_path.stem
    program_data['functions'] = []
    
    executable_name = executable_path.stem
    
    # -- Acquire ASM and create a dictionary of function_name -> asm
    asm_dict = {f.name: f.instructions for f in get_asm_list(executable_path)}
    ghidra_dict = get_ghidra_dict(executable_path)
    
    
    # -- Acquire SOG and Call Graph    
    output_dir = create_cfg_output_dir(executable_name)
    cfg_map = g.extract_cfg(executable_path, output_dir)
    callgraph_map = g.extract_call_graph(executable_path, output_dir)
    
    # -- Topologically Sort Call Graph
    callgraph = build_call_graph(callgraph_map.get('call_graph'))
    sorted_functions = topological_sort(callgraph)
    program_data['callgraph'] = callgraph
    
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
        
        # LLM Guided Enrichment for Summary and Optimized Code
        '''
        Summary for function : Should pass in Ghidra Code, ASM
        Optimize Code for function : Should pass in Ghidra Code, Summary, SOG
        '''
        f_data['function_summary'] = gen_code_summary(
            asm=f_data['asm'],
            ghidra=f_data['ghidra_code'] 
        )
        f_data['optimization_status'], f_data['optimized_code'] = get_optimized_code(
            c_code=f_data['ghidra_code'],
            function_summary=f_data['function_summary'],
            caller_and_callee_summary="",
            function_sog=f_data['sog_dot'],
            language="c",
            llm_interface=llm_interface,
            max_iterations=3
        )
        functions.append(f_data)
        
    program_data['functions'] = functions
        
    return program_data


def combine_enrichment(program_data: Dict) -> str:
    combined_code = get_program_code(program_data)
    '''
    Summary for program : Should pass in combined code
    Summary for caller_callee_context : Should pass in caller and callee graph
    Summary for optimized code : Should pass in program code, summary, caller callee context summary
    '''
    # get program summary
    program_summary = gen_code_summary(
        asm="",
        ghidra=combined_code
    )
    # get caller callee context summary
    context_summary = gen_context_summary(
        callgraph=program_data['callgraph']
    )
    # get optimized program code
    status, optimized_program_code = get_optimized_code(
        c_code=combined_code,
        function_summary=program_summary,
        caller_and_callee_summary=context_summary,
        function_sog="",
        language="c",
        llm_interface=llm_interface,
        max_iterations=3
    )
    program_data['program_summary'] = program_summary
    program_data['context_summary'] = context_summary
    program_data['optimized_code'] = optimized_program_code
    program_data['optimization_status'] = status
    
    
    return program_data

def gen_context_summary(callgraph: Dict[str, List[str]]) -> str:
    '''
    context_prompt = config["prompts"]["context_prompt"]
    prompt = f"{context_prompt}\n\nCall Graph:\n"
    for function, callees in callgraph.items():
        prompt += f"{function} calls {', '.join(callees) if callees else 'no functions'}\n"
    
    # Call the LLM API to generate a summary
    response = llm_interface.generate(prompt)
    '''
    prompt = ""
    for function, callees in callgraph.items():
        prompt += f"{function} calls {', '.join(callees) if callees else 'no functions'}\n"
    return prompt


def gen_code_summary(asm: str, ghidra: str) -> str:
    summary_prompt = config["prompts"]["summary_prompt"]
    prompt = f"{summary_prompt}"
    if ghidra:
        prompt += f"\n\nGhidra Code:\n```c\n{ghidra}\n```"
    if asm:
        prompt += f"\n\nAssembly Instructions:\n{asm}"

    # Call the LLM API to generate a summary
    response = llm_interface.generate(prompt)
    return response

    
def main():
    data_dir = Path(config["paths"]["test_path"])
    test_executable = data_dir / "test_3"
    data = split_enrichment(test_executable)
    data = combine_enrichment(data)
    
    with open(str(Path(output_dir) / f"enriched_data_{test_executable.stem}.json"), "w") as f:
        json.dump(data, f, indent=4)

if __name__ == "__main__":
    main()