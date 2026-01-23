# Jython script for Ghidra 11.0.3  
from ghidra.program.model.listing import FunctionManager 
import os 
import sys


  
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
  # Create subdirectory for this program
  program_dir = os.path.join(output_dir, program.getName())
  if not os.path.exists(program_dir):
    os.makedirs(program_dir)
  
  output_path = os.path.join(program_dir, "call_graph.dot")
  with open(output_path, 'w') as f:  
    f.write('digraph CallGraph {\n')  
    for caller, data in call_graph.items():  
      for callee in data['calls']:  
        f.write("{%s} -> {%s};\n" % (caller, callee))
    f.write('}\n')  
  
# Execute  
call_graph = get_call_graph()  
# Read output_dir from command-line argument (passed via -postScript)
output_dir = sys.argv[1] if len(sys.argv) > 1 else "/tmp"
export_to_dot(call_graph, output_dir, currentProgram)