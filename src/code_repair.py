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



def get_initial_prompt(c_code: str, summary: str,language: str) -> str:
  """
  Generate the initial prompt for the repair tool given C code of the particular function.
  """
  initial_prompt = config["prompts"]["system_prompt"]
  prompt = f"{initial_prompt}\n\n```Language:{language}\nSummary:{summary}\n{c_code}\n```"
  return prompt


def get_optimized_code(original_c_code: str, summary: str, language: str, max_iterations: int, llm_interface: LLMInterface ) -> str:
  """
  Generate optimized C code using LLM for the given original C code file.
  """
  
  compilable_code = original_c_code
  
  # handle everything in a temporary directory
  with tempfile.TemporaryDirectory() as temp_dir:
    # write the original code to a file
    original_c_file = Path(temp_dir) / "original.c"
    with open(original_c_file, "w") as f:
      f.write(original_c_code)
    
    # check if original code compiles
    status, message = c.compile_source(
      source_file_path = original_c_file,
      output_file_path = Path(temp_dir) / "original.out",
      opt = OptimizationLevel.O0,
      is_cpp = (language == "cpp")
    )
  
    if status:
      print("Original Ghidra Code compiles successfully. No optimization needed.")
      return True, original_c_code

    
    # if not, provide an initial LLM optimization
    print("Original Ghidra Code does not compile. Starting optimization...")
    initial_prompt = get_initial_prompt(original_c_code,summary,language)
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
      repair_prompt = f"{config['prompts']['compilation_error']}\n\n```c\nLanguage:{language}\nSummary:{summary}\nCode:{optimized_code}\n```\n\nCompilation Errors:\n{error_prompt}\n\nPlease provide the corrected C code."
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
