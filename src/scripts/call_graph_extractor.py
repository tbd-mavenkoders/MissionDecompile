# Jython script for Ghidra 11.0.3  
from ghidra.program.model.listing import FunctionManager 
import os 


  
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
  
# Execute  
call_graph = get_call_graph()  
export_to_dot(call_graph, "/workspace/home/aiclub1/B220032CS_Jaefar/fyp/repos/ansaf/MissionDecompile/output/SOG", currentProgram)