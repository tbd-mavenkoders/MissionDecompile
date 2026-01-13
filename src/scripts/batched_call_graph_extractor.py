# Jython script for Ghidra 11.0.3 - Batch Call Graph Extraction
# This script processes the current program and extracts call graph
from ghidra.program.model.listing import FunctionManager 
import os 
import json

def get_call_graph():  
  fm = currentProgram.getFunctionManager()  
  call_graph = {}  
    
  for function in fm.getFunctions(True):  
    called_functions = function.getCalledFunctions(None)  
    calling_functions = function.getCallingFunctions(None)  
      
    call_graph[function.getName()] = {  
        'calls': [f.getName() for f in called_functions],  
        'called_by': [f.getName() for f in calling_functions]  
    }  
    
  return call_graph  
  
# Export to DOT  
def export_to_dot(call_graph, output_dir, program):
  output_path = os.path.join(output_dir, program.getName(), "call_graph.dot")
  with open(output_path, 'w') as f:  
    f.write('digraph CallGraph {\n')  
    for caller, data in call_graph.items():  
      for callee in data['calls']:  
        f.write("{%s} -> {%s};\n" % (caller, callee))
    f.write('}\n')

# Export to JSON
def export_to_json(call_graph, output_dir, program):
  output_path = os.path.join(output_dir, program.getName(), "call_graph.json")
  with open(output_path, 'w') as f:
    json.dump({'call_graph': call_graph}, f, indent=2)
  
# Execute  
program = currentProgram
print("Processing program:", program.getName())

# Get output directory from script arguments or use default
if len(getScriptArgs()) > 0:
    output_dir = getScriptArgs()[0]
else:
    output_dir = "/workspace/home/aiclub1/B220032CS_Jaefar/fyp/repos/ansaf/MissionDecompile/output/SOG"

# Ensure output directory exists
outdir = os.path.join(output_dir, program.getName())
if not os.path.exists(outdir):
    os.makedirs(outdir)

call_graph = get_call_graph()  
export_to_dot(call_graph, output_dir, program)
export_to_json(call_graph, output_dir, program)

print("Finished processing:", program.getName())
