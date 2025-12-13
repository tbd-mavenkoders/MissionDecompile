import tempfile
from typing import Tuple
from ..utils.clean_errors import ErrorNormalizer
from ..utils.llm_interface import create_llm_interface, LLMInterface
from ..utils.compile import Compiler, OptimizationLevel
from pathlib import Path
from ..utils.logger import setup_logger
import yaml




c = Compiler()



# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)



def get_initial_prompt(c_code: str, function_summary: str, caller_and_callee_summary: str, function_sog: str, language: str) -> str:
  """
  Generate the initial prompt for the repair tool given C code of the particular function.
  """
  initial_prompt = config["prompts"]["system_prompt"]
  prompt = f"{initial_prompt}\n\n```Language:{language}\nSummary:{function_summary}\n{c_code}\n```"
  if caller_and_callee_summary:
    prompt += f"\n\nCaller and Callee Summary:\n{caller_and_callee_summary}"
  if function_sog:
    prompt += f"\n\nFunction SOG:\n{function_sog}"
  return prompt


def get_repair_prompt(c_code: str, compilation_errors: str, function_summary: str, caller_and_callee_summary: str, function_sog: str, language: str) -> str:
  """
  Generate the repair prompt for the repair tool given C code of the particular function and compilation errors.
  """
  repair_prompt = config["prompts"]["compilation_error"]
  prompt = f"{repair_prompt}\n\n```c\nLanguage:{language}\nSummary:{function_summary}\nCode:{c_code}\n```\n\nCompilation Errors:\n{compilation_errors}\n\nPlease provide the corrected C code."
  if caller_and_callee_summary:
    prompt += f"\n\nCaller and Callee Summary:\n{caller_and_callee_summary}"
  if function_sog:
    prompt += f"\n\nFunction SOG:\n{function_sog}"
  return prompt

def get_optimized_code(c_code: str, function_summary: str, caller_and_callee_summary: str, function_sog: str, language: str, max_iterations: int, llm_interface: LLMInterface ) -> str:
  """
  Generate optimized C code using LLM for the given original C code file.
  """
    
  # handle everything in a temporary directory
  with tempfile.TemporaryDirectory() as temp_dir:
    # write the original code to a file
    original_c_file = Path(temp_dir) / "original.c"
    with open(original_c_file, "w") as f:
      f.write(c_code)
    
    # check if original code compiles
    status, message = c.compile_source(
      source_file_path = original_c_file,
      output_file_path = Path(temp_dir) / "original.out",
      opt = OptimizationLevel.O0,
      is_cpp = (language == "cpp")
    )
  
    if status:
      print("Original Ghidra Code compiles successfully. No optimization needed.")
      return True, c_code

    
    # if not, provide an initial LLM optimization
    print("Original Ghidra Code does not compile. Starting optimization...")
    initial_prompt = get_initial_prompt(
      c_code=c_code,
      function_summary=function_summary,
      caller_and_callee_summary=caller_and_callee_summary,
      function_sog=function_sog,
      language=language
      )
    
    optimized_code = llm_interface.generate(initial_prompt)
    
    # check if initially prompted code compiles
    original_c_file.write_text(optimized_code)
    status, message = c.compile_source(
      source_file_path = original_c_file,
      output_file_path = Path(temp_dir) / "optimized.out",
      opt = OptimizationLevel.O0,
      is_cpp = (language == "cpp")
    )
    
    if status:
      print("Optimized code compiles successfully after initial LLM prompt.")
      return True, optimized_code
    
    # begin static repair loop
    for iteration in range(max_iterations):
      print(f"Static Repair Iteration {iteration + 1}...")
      
      # acquire optimized output through error passing
      e = ErrorNormalizer()
      error_prompt = e.format_for_llm(message)
      repair_prompt = get_repair_prompt(
        c_code=optimized_code,
        compilation_errors=error_prompt,
        function_summary=function_summary,
        caller_and_callee_summary=caller_and_callee_summary,
        function_sog=function_sog,
        language=language
      )
      optimized_code = llm_interface.generate(repair_prompt)
      
      # check if it compiles
      original_c_file.write_text(optimized_code)
      status, message = c.compile_source(
        source_file_path = original_c_file,
        output_file_path = Path(temp_dir) / "optimized.out",
        opt = OptimizationLevel.O0,
        is_cpp = (language == "cpp")
      )
      
      if status:
        print(f"Optimized code compiles successfully after {iteration + 1} iterations.")
        return True, optimized_code
      else:
        print(f"Optimized code still does not compile after iteration {iteration + 1}. Continuing...")
    
      
    print("Max optimization iterations reached. Returning last optimized code.")
    return False, optimized_code
