from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor
import json
import os

def get_block_instructions(block, program):
  listing = program.getListing()
  addr = block.getFirstStartAddress()

  ins = []
  instr = listing.getInstructionAt(addr)
  
  while instr and block.contains(instr.getMinAddress()):
    ops = []
    for i in range(instr.getNumOperands()):
      ops.extend([str(x) for x in instr.getOpObjects(i)])
    ins.append({
      "address": str(instr.getMinAddress()),
      "mnemonic": instr.getMnemonicString(),
      "proto": instr.toString(),
      "ops": ops
    })
    instr = instr.getNext()

  return ins


def extract_cfg(func, program, monitor):
  bbm = BasicBlockModel(program)
  blocks_it = bbm.getCodeBlocks(monitor)
  func_body = func.getBody()

  cfg = {
    "function_name": func.getName(),
    "entry": str(func.getEntryPoint()),
    "blocks": [],
    "edges": []
  }

  id_map = {}
  idx = 0

  # collect blocks
  func_blocks = []
  while blocks_it.hasNext():
    block = blocks_it.next()
    if func_body.intersects(block.getFirstStartAddress(), block.getMaxAddress()):
      bid = "B" + str(idx)
      id_map[block] = bid

      cfg["blocks"].append({
        "id": bid,
        "start": str(block.getFirstStartAddress()),
        "instructions": get_block_instructions(block, program)
      })

      idx += 1
      func_blocks.append(block)

  # collect edges
  for block in func_blocks:
    src = id_map[block]
    dests = block.getDestinations(monitor)
    while dests.hasNext():
      d = dests.next()
      dst_block = d.getDestinationBlock()
      if dst_block is None:
        continue

      dst = id_map.get(dst_block)
      if dst:
        cfg["edges"].append({
          "src": src,
          "dst": dst,
          "type": str(d.getFlowType())
        })
  return cfg


# Write all functions
monitor = getMonitor()
program = currentProgram
outdir = "/workspace/home/aiclub1/B220032CS_Jaefar/fyp/repos/ansaf/MissionDecompile/output/SOG"
outdir = os.path.join(outdir, program.getName())
os.mkdir(outdir) if not os.path.exists(outdir) else None


fm = program.getFunctionManager()
funcs = fm.getFunctions(True)
for f in funcs:
  try:
      sog = extract_cfg(f, program, monitor)
      out = os.path.join(outdir, f.getName() + ".json")
      with open(out, "w") as fp:
        json.dump(sog, fp, indent=2)
      print("Saved SOG:", f.getName())
  except Exception as e:
      print("Skipping", f.getName(), "due to", e)