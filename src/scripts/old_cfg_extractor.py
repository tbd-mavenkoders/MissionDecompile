from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor
import os

def export_to_dot(func, program, out_path, monitor):
  print("== Exporting CFG for function:", func.getName())
  bbm = BasicBlockModel(program)  # Use BasicBlockModel
  print("== BasicBlockModel created")
  body = func.getBody()
  print("== Function body obtained")
  blocks = bbm.getCodeBlocks(monitor)  # pass TaskMonitor.DUMMY
  print("== Code blocks obtained")
  nodes = []
  edges = []
  # We'll also collect additional metadata per block: start, end, size, sample mnemonic
  listing = program.getListing()
  while blocks.hasNext():
    block = blocks.next()
    start = block.getFirstStartAddress()
    end = block.getMaxAddress()
    # number of code-unit elements (typically instructions)
    try:
      size = block.getNumElements()
    except Exception:
      size = 0
    # try to get a sample mnemonic at the block start
    try:
      instr = listing.getInstructionAt(start)
      mnem = instr.getMnemonicString() if instr is not None else ''
    except Exception:
      mnem = ''
    nodes.append((str(start), str(end), int(size), str(mnem)))
    refs = block.getDestinations(TaskMonitor.DUMMY)  # also pass TaskMonitor.DUMMY
    while refs.hasNext():
      ref = refs.next()
      target = ref.getDestinationBlock()
      if target is None:
        continue
      edges.append((str(start), str(target.getFirstStartAddress())))
  print("== Nodes and edges collected")
  with open(out_path, 'w') as f:
    # Add a graph-level label with function metadata
    try:
      entry = func.getEntryPoint()
    except Exception:
      entry = ''
    fname = func.getName()
    f.write('digraph G {\n')
    f.write('labelloc="t";\n')
    f.write('label="Function: %s\nEntry: %s";\n' % (fname, entry))
    # Write nodes with richer labels
    for n, e, sz, m in nodes:
      # escape quotes
      label = '%s\\nend=%s\\nsize=%s\\nmnemonic=%s' % (n, e, sz, m)
      f.write('"%s" [label="%s"];\n' % (n, label))
    # Write edges
    for s,t in edges:
      f.write('"%s" -> "%s";\n' % (s,t))
    f.write('}\n')

monitor = getMonitor()
funcs = currentProgram.getFunctionManager().getFunctions(True)
outdir = "/workspace/home/aiclub1/B220032CS_Jaefar/fyp/repos/ansaf/MissionDecompile/output/CFG"
if not os.path.exists(outdir):
  os.makedirs(outdir)
# create subfolder with name as executable name
outdir = os.path.join(outdir, currentProgram.getName())
if not os.path.exists(outdir):
  os.makedirs(outdir)

for func in funcs:
  try:
    name = func.getName()
    safe = ''.join([c if c.isalnum() else '_' for c in name])
    out = os.path.join(outdir, safe + '.dot')
    export_to_dot(func, currentProgram, out, monitor)
  except Exception as e:
    print('Skipping function', func, 'due to', e)
