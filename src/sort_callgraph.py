"""
Sorts the call graph of the program in a topological fashion for better prompting.
digraph CallGraph {
{knapsack} -> {max};
{knapsack} -> {__stack_chk_fail};
}
"""
from typing import Dict, List

def build_call_graph(call_graph_path):
  call_graph: Dict[str, List[str]] = {}
  
  with open(call_graph_path, 'r') as f:
    lines = f.readlines()
  for line in lines:
    line = line.strip()
    if '->' in line:
      parts = line.replace('{','').replace('}','').replace(';','').split('->')
      caller = parts[0].strip()
      callee = parts[1].strip()
      if caller not in call_graph:
        call_graph[caller] = []
      call_graph[caller].append(callee)
  return call_graph
      
def topological_sort(call_graph: Dict[str, List[str]]) -> List[str]:
  # Create Indegree Dictionary
  indegree = {}
  for node in call_graph:
    if node not in indegree:
      indegree[node] = 0
    for neighbor in call_graph[node]:
      if neighbor not in indegree:
        indegree[neighbor] = 0
      indegree[neighbor] += 1
  # Initialize Queue with nodes of indegree 0
  q = [node for node in indegree if indegree[node] == 0]
  sorted_order = []
  while q:
    current = q.pop(0)
    sorted_order.append(current)
    for neighbor in call_graph.get(current, []):
      indegree[neighbor] -= 1
      if indegree[neighbor] == 0:
        q.append(neighbor)
  return sorted_order
