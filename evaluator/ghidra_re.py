import yaml
from pathlib import Path
from ..utils.compile import Compiler,OptimizationLevel
import re
import shutil
import tempfile
import os
from typing import Tuple, List, Dict
import json
import subprocess
from ..utils.llm_interface import create_llm_interface


c = Compiler()


# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
print(f"Loading config from: {CONFIG_PATH}")

with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

corpus_path = Path(config["humaneval"]["corpus_path"])
output_path = Path(config["humaneval"]["output_path"])

llm_interface = create_llm_interface(
  provider=config["llm"]["vllm_provider"],
  model_name=config["llm"]["vllm_model_name"],
  base_url=config["llm"]["vllm_base_url"]
)

def compile_and_execute(c_file_path: str, language: str) -> Tuple[bool, bool, str]:
  """
  Compile and execute the C code, returning any runtime errors.
  """
  output_executable = c_file_path.with_suffix('')
  status, compile_message = c.compile_source(
    source_file_path = c_file_path,
    output_file_path = output_executable,
    opt = OptimizationLevel.O0,
    is_cpp = (language == "cpp"),
    c_flag = False,
    extra_flags = ["-lm"]
  )
  # if fails to compile, return error
  if not status:
    return False, False, compile_message
  # if compiles, run and capture output by running ./output_executable
  try:
    command = [f"./{output_executable.name}"]
    print("Executing command:", " ".join(command))
    res = subprocess.run(command, cwd = output_executable.parent, capture_output=True, text=True, timeout=5)
    if res.returncode == 0:
      return True, True, res.stdout
    else:
      return True, False, res.stderr
  except Exception as e:
    return True, False, str(e)
  



def process_json_file(corpus_file: Path, output_file: Path) -> Dict:
  stats = {}
  c_stats = {}
  cpp_stats = {}
  
  
  # Load the JSON file
  with open(corpus_file, "r") as f:
    corpus = json.load(f)
  with open(output_file, "r") as out_f:
    output = json.load(out_f)
    
  for data in corpus:
    log = {}
    corpus_index = data["index"]
    optimized_code = ""
    ghidra_code = data["ghidra_pseudo"]
    c_include = ""
    test_code = data["test"]
    c_include += data["func_dep"] + "\n"
    
       
    
    # get the includes from data["optimized_func"] and data["test"]
    opt = data["opt"]
    stats.setdefault(opt, {"total":0, "compilation_failures":0, "execution_failures":0, "successful_executions":0})
    c_stats.setdefault(opt, {"total":0, "compilation_failures":0, "execution_failures":0, "successful_executions":0})
    cpp_stats.setdefault(opt, {"total":0, "compilation_failures":0, "execution_failures":0, "successful_executions":0})
    print(f"Processing index: {corpus_index}")
    c_optimized = optimized_code
    c_test = test_code
    
    stats[opt]["total"] += 1
    if data["language"] == "c":
      c_stats[opt]["total"] += 1
    else:
      cpp_stats[opt]["total"] += 1
    
    includes = ""
    # get includes in test code
    for line in test_code.splitlines():
      if "include" in line:
        includes += line + "\n"
        c_test = c_test.replace(line,"")
    # get includes in ghidra code
    for line in ghidra_code.splitlines():
      if "include" in line:
        includes += line + "\n"
        ghidra_code = ghidra_code.replace(line,"")
        
    original_c_code = includes + data["ghidra_pseudo"] + "\n" + c_test
    #print(f"ORIGINAL C CODE : {original_c_code}")
    language = data["language"]
    
    with tempfile.TemporaryDirectory() as temp_dir:
      temp_dir_path = Path(temp_dir)
      c_file_path = temp_dir_path / f"temp_code.{'cpp' if language == 'cpp' else 'c'}"
      with open(c_file_path, "w") as f:
        f.write(original_c_code)
            
      # attempt to compile and execute the original code
      compiled, executed, runtime_message = compile_and_execute(c_file_path, language)
      if not compiled:
        print("Compilation Error : ", runtime_message)
        stats[opt]["compilation_failures"] += 1
        if data["language"] == "c":
          c_stats[opt]["compilation_failures"] += 1
        else:
          cpp_stats[opt]["compilation_failures"] += 1
      elif compiled and executed:
        stats[opt]["successful_executions"] += 1
        if data["language"] == "c":
          c_stats[opt]["successful_executions"] += 1
        else:
          cpp_stats[opt]["successful_executions"] += 1
      else:
        stats[opt]["execution_failures"] += 1
        if data["language"] == "c":
          c_stats[opt]["execution_failures"] += 1
        else:
          cpp_stats[opt]["execution_failures"] += 1
        print("Error : ", runtime_message)
        
    '''
    if not compiled or not executed:
      log["runtime_message"] = runtime_message
      prompt = config["prompts"]["analysis_prompt"] + "\n\n" + str(log)
      error_analysis = json.loads(llm_interface.generate(prompt))
      error_analysis["original_code"] = data["original_code"]
      error_analysis["optimized_code"] = optimized_code
      
      # append to json file
      analysis_path = output_path / "analysis_logs.json"
      
      if analysis_path.exists():
        with open(analysis_path, "r") as f:
          existing_data = json.load(f)
        existing_data.append(error_analysis)
        with open(analysis_path, "w") as f:
          json.dump(existing_data, f, indent=4)
      else:
        with open(analysis_path, "w") as f:
          json.dump([error_analysis], f, indent=4)
    '''

        
    # print rates for every optimization level
    for opt_level, opt_stats in stats.items():
      total_opt = opt_stats["total"]
      c_fail_opt = opt_stats["compilation_failures"]
      e_fail_opt = opt_stats["execution_failures"]
      ce_success_opt = opt_stats["successful_executions"]
      if total_opt > 0:
        print(f"Optimization Level: {opt_level} | Compilation failures: {c_fail_opt} | Execution failures: {e_fail_opt} | Successful executions: {ce_success_opt} out of {total_opt} | Rate : {ce_success_opt/total_opt*100:.2f}%\n")
        
    # print C rates
    for opt_level, opt_stats in c_stats.items():
      total_opt = opt_stats["total"]
      c_fail_opt = opt_stats["compilation_failures"]
      e_fail_opt = opt_stats["execution_failures"]
      ce_success_opt = opt_stats["successful_executions"]
      if total_opt > 0:
        print(f"[C] Optimization Level: {opt_level} | Compilation failures: {c_fail_opt} | Execution failures: {e_fail_opt} | Successful executions: {ce_success_opt} out of {total_opt} | Rate : {ce_success_opt/total_opt*100:.2f}%\n")
        
    # print average C rate
    avg_rate = 0
    for opt_level, opt_stats in c_stats.items():
      total_opt = opt_stats["total"]
      ce_success_opt = opt_stats["successful_executions"]
      if total_opt > 0:
        avg_rate += (ce_success_opt/total_opt*100)
    avg_rate = avg_rate / len(c_stats)
    print(f"Average C Successful Execution Rate across all optimization levels: {avg_rate:.2f}%\n")
        
    # print C++ rates
    for opt_level, opt_stats in cpp_stats.items():
      total_opt = opt_stats["total"]
      c_fail_opt = opt_stats["compilation_failures"]
      e_fail_opt = opt_stats["execution_failures"]
      ce_success_opt = opt_stats["successful_executions"]
      if total_opt > 0:
        print(f"[C++] Optimization Level: {opt_level} | Compilation failures: {c_fail_opt} | Execution failures: {e_fail_opt} | Successful executions: {ce_success_opt} out of {total_opt} | Rate : {ce_success_opt/total_opt*100:.2f}%\n")
        
    # print average C++ rate
    avg_rate = 0
    for opt_level, opt_stats in cpp_stats.items():
      total_opt = opt_stats["total"]
      ce_success_opt = opt_stats["successful_executions"]
      if total_opt > 0:
        avg_rate += (ce_success_opt/total_opt*100)
    avg_rate = avg_rate / len(cpp_stats)
    print(f"Average C++ Successful Execution Rate across all optimization levels: {avg_rate:.2f}%\n")
        
    # print average optimization rate
    avg_rate = 0
    for opt_level, opt_stats in stats.items():
      total_opt = opt_stats["total"]
      ce_success_opt = opt_stats["successful_executions"]
      if total_opt > 0:
        avg_rate += (ce_success_opt/total_opt*100)
    avg_rate = avg_rate / len(stats)
    print(f"Average Successful Execution Rate across all optimization levels: {avg_rate:.2f}%\n")
      
    
  return stats
    
    
def main():
  """
  Main function to process all JSON files in the corpus root directory.
  """
  
  corpus_file = corpus_path / "humaneval-decompile.json"
  output_file = "/workspace/home/b220032cs/fyp/repos/ansaf/Experiments/v0-SinglePrompt/VERITAS/output/humaneval-decompile/v0_120b_batched_enriched_humaneval_decompile.json"
  stats = process_json_file(corpus_file, output_file)
        


if __name__ == "__main__":
  main()
