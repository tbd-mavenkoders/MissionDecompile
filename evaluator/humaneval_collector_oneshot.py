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
from ..src.sort_callgraph import build_call_graph, topological_sort
from ..utils.c_program_parser import create_ghidra_dict
from ..utils.disassembler import Disassembler
from ..src.code_repair import get_optimized_code

# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)
    
    
c = Compiler()
g = Ghidra()
d = Disassembler()

'''
llm_interface = create_llm_interface(
    provider=config["llm"]["vllm_provider"],
    model_name=config["llm"]["vllm_model_name"],
    base_url=config["llm"]["vllm_base_url"]
)
'''
llm_interface = create_llm_interface(
    provider=config["llm"]["gemini_provider"],
    model_name=config["llm"]["gemini_model_name"],
    api_key=config["llm"]["gemini_api_key"]
)

corpus_path = Path(config["humaneval"]["corpus_path"])
output_dir = Path(config["humaneval"]["output_path"])


def create_cfg_output_dir(executable_name: str) -> Path:
    output_dir = Path(config["humaneval"]["output_path"]) / "SOG" / executable_name
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir
    
  
def split_enrichment(data: Dict,executable_path: Path):
    program_data = {}
    program_data['index'] = data['index']
    program_data['language'] = data['language']
    program_data['original_code'] = data['func']
    program_data['executable_name'] = executable_path.stem
    program_data['test'] = data['test']
    program_data['func_dep'] = data['func_dep']
    program_data['functions'] = []
    
    executable_name = executable_path.stem
    
    
    # -- For each function in topological order, enrich its SOG using LLM
    functions = []
    sorted_functions = ["func0"]
    for function_name in sorted_functions:
        
        if function_name != "func0":
            continue
        
        f_data = {}
        f_data['f_name'] = function_name
        f_data['asm'] = data['asm']
        f_data['ghidra_code'] = data['ghidra_pseudo']
        
        
        # LLM Guided Enrichment for Summary and Optimized Code
        print(f"Optimizing Function:{function_name}")

        
    
        f_data['optimization_status'], f_data['optimized_code'] = get_optimized_code(
            c_code=f_data['ghidra_code'],
            function_summary="",
            caller_and_callee_summary="",
            function_sog="",
            language=data['language'],
            llm_interface=llm_interface,
            max_iterations=0,
            c_flag=True
        )
        
        functions.append(f_data)
        
    program_data['functions'] = functions
        
    return program_data



def single_function_optimizer(data: Dict) -> Dict:
    '''
    Creates the executable from the decompiled C code and store it in a temporary directory.
    '''
    c_program = data['func_dep'] + data['func']
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        c_file_path = temp_path / f"temp.{'cpp' if data['language']=='cpp' else 'c'}"
        executable_path = temp_path / "temp_executable"
        with open(c_file_path, "w") as f:
            f.write(c_program)
        status, message = c.compile_source(
            source_file_path=str(c_file_path),
            output_file_path=str(executable_path),
            opt=OptimizationLevel.O0,
            is_cpp=(data['language'] == "cpp"),
            c_flag=True
        )
        if not status:
            print(f"Compilation failed for function index {data['index']}: {message}")
            return {}
        # If compilation is successful, perform split enrichment
        enriched_data = split_enrichment(data, executable_path)
        return enriched_data
    
def process_humaneval_decompile(json_path: Path) -> List[Dict]:
    '''
    Process the humaneval decompile json file and enrich each function's data.
    '''
    output_file_path = output_dir / "v0_actual_gemini_humaneval_decompile.json"
    output_file_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(json_path, "r") as f:
        humaneval_data = json.load(f)
    
    for item in humaneval_data:
        if item['index'] <= 612:
            continue
        print(f"Processing function index: {item['index']}")
        enriched_data = single_function_optimizer(item)
        # append to json file
        if output_file_path.exists():
            with open(output_file_path, "r") as f:
                existing_data = json.load(f)
            existing_data.append(enriched_data)
            with open(output_file_path, "w") as f:
                json.dump(existing_data, f, indent=4)
        else:
            with open(output_file_path, "w") as f:
                json.dump([enriched_data], f, indent=4)
             
       

def main():
    json_path = corpus_path / "humaneval-decompile.json"
    process_humaneval_decompile(json_path)
    
    
    
if __name__ == "__main__":
    main()
    
    

