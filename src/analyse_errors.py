import yaml
from pathlib import Path
import re
import shutil
import tempfile
import os
from typing import Tuple, List, Dict
import json





# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)
    
    

output_path = Path(config["humaneval"]["output_path"])


def main():
  json_path = output_path / "analysis_logs.json"
  with open(json_path, "r") as f:
      analysis_logs = json.load(f)
  '''
  sample data
  
    {
        "index": 16,
        "errors": [
            {
                "error": true,
                "error_phase": "LLM Optimization Issue",
                "error_type": "type_mismatch",
                "type_mismatch_details": [
                    {
                        "expected_type": "float",
                        "actual_type": "void",
                        "location": "return type",
                        "code_snippet": "void func0(std::vector<float> param_1)\n{\n    if (param_1.empty())\n        return;\n    // ..."
                    }
                ],
                "error_summary": "Optimized code changed func0's return type from float to void, causing compilation errors when the test code attempts to use its returned value in arithmetic."
            }
        ],
        "original_code": "float func0(vector<float> numbers){\n    float sum=0;\n    float avg,msum,mavg;\n    int i=0;\n    for (i=0;i<numbers.size();i++)\n        sum+=numbers[i];\n    avg=sum/numbers.size();\n    msum=0;\n    for (i=0;i<numbers.size();i++)\n        msum+=abs(numbers[i]-avg);\n    return msum/numbers.size();\n}\n\n",
        "optimized_code": "#include <vector>\n#include <cmath>\n\nvoid func0(std::vector<float> param_1)\n{\n    if (param_1.empty())\n        return;\n\n    float sum = 0.0f;\n    for (float v : param_1) {\n        sum += v;\n    }\n\n    float mean = sum / static_cast<float>(param_1.size());\n\n    float abs_sum = 0.0f;\n    for (float v : param_1) {\n        abs_sum += std::fabs(v - mean);\n    }\n\n    (void)abs_sum;\n}"
    },
  '''
  # Create a map of errors and their counts
  error_map = {}
  for log in analysis_logs:
    error = log.get("errors", [])
    if not error:
      continue
    error = error[0]
    error_type = error["error_type"]
    if error_type not in error_map:
      error_map[error_type] = {
          "count": 0,
      }
    error_map[error_type]["count"] += 1
    
  # Print the error map
  for error_type, details in error_map.items():
    print(f"Error Type: {error_type}, Count: {details['count']}")
    
  # Create a map of which error phases are associated with each case
  error_phase_map = {}
  for log in analysis_logs:
    error = log.get("errors", [])
    if not error:
      continue
    error = error[0]
    error_phase = error["error_phase"]
    if error_phase not in error_phase_map:
      error_phase_map[error_phase] = {
        "count": 0,
      }
    error_phase_map[error_phase]["count"] += 1
    
  # Print the error phase map
  for error_phase, details in error_phase_map.items():
    print(f"Error Phase: {error_phase}, Count: {details['count']}")
      

if __name__ == "__main__":
    main()