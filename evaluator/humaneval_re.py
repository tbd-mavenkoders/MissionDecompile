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


c = Compiler()


# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
print(f"Loading config from: {CONFIG_PATH}")

with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

corpus_path = Path(config["humaneval"]["corpus_path"])
output_path = Path(config["humaneval"]["output_path"])


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
    c_flag = False
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
  ce_success = 0
  c_fail = 0
  e_fail = 0
  total = 0
  """
  Process a single JSON file containing decompiled C code and attempt to optimize it.
    {
        "index": 730,
        "func_name": "func0",
        "func_dep": "#include <stdio.h>\n#include <string.h>\n",
        "func": "int func0(const char *str, const char *substring) {\n    int out = 0;\n    int str_len = strlen(str);\n    int sub_len = strlen(substring);\n    if (str_len == 0) return 0;\n    for (int i = 0; i <= str_len - sub_len; i++) {\n        if (strncmp(&str[i], substring, sub_len) == 0)\n            out++;\n    }\n    return out;\n}",
        "test": "#include <assert.h>\n\nint main() {\n    assert(func0(\"\", \"x\") == 0);\n    assert(func0(\"xyxyxyx\", \"x\") == 4);\n    assert(func0(\"cacacacac\", \"cac\") == 4);\n    assert(func0(\"john doe\", \"john\") == 1);\n\n    return 0;\n}",
        "opt": "O2",
        "language": "c",
        "asm": "func0:\nendbr64\npush   %r14\npush   %r13\npush   %r12\nmov    %rsi,%r12\npush   %rbp\npush   %rbx\nmov    %rdi,%rbx\ncallq  1080 <strlen@plt>\nmov    %eax,%r14d\ntest   %eax,%eax\nje     12de <func0+0x5e>\nmov    %r12,%rdi\nmov    %rax,%r13\ncallq  1080 <strlen@plt>\nsub    %eax,%r13d\njs     12f0 <func0+0x70>\nmovslq %r13d,%r13\nmovslq %eax,%rbp\nxor    %r14d,%r14d\nlea    0x1(%rbx,%r13,1),%r13\nnopl   0x0(%rax)\nmov    %rbx,%rdi\nmov    %rbp,%rdx\nmov    %r12,%rsi\ncallq  1070 <strncmp@plt>\ncmp    $0x1,%eax\nadc    $0x0,%r14d\nadd    $0x1,%rbx\ncmp    %r13,%rbx\njne    12c0 <func0+0x40>\npop    %rbx\nmov    %r14d,%eax\npop    %rbp\npop    %r12\npop    %r13\npop    %r14\nretq\nnopw   0x0(%rax,%rax,1)\nxor    %r14d,%r14d\njmp    12de <func0+0x5e>\nnopw   %cs:0x0(%rax,%rax,1)\n",
        "ida_asm": "func0:\nendbr64\npush    r14\npush    r13\nmov     r13, rsi\npush    r12\npush    rbp\npush    rbx\nmov     rbx, rdi\ncall    _strlen\nmov     ebp, eax\ntest    eax, eax\njz      short loc_12DD\nmov     rdi, r13; s\nmov     r14, rax\ncall    _strlen\nsub     r14d, eax\njs      short loc_12F0\nmovsxd  r14, r14d\nmovsxd  r12, eax\nxor     ebp, ebp\nlea     r14, [rbx+r14+1]\nnop     word ptr [rax+rax+00h]\nloc_12C0:\nmov     rdi, rbx; s1\nmov     rdx, r12; n\nmov     rsi, r13; s2\ncall    _strncmp\ncmp     eax, 1\nadc     ebp, 0\nadd     rbx, 1\ncmp     rbx, r14\njnz     short loc_12C0\nloc_12DD:\npop     rbx\nmov     eax, ebp\npop     rbp\npop     r12\npop     r13\npop     r14\nretn\nloc_12F0:\nxor     ebp, ebp\njmp     short loc_12DD",
        "ida_pseudo": "long long  func0(char *s1, char *s2)\n{\n  const char *v2; // rbx\n  unsigned int v3; // eax\n  unsigned int v4; // ebp\n  unsigned int v5; // r14d\n  int v6; // eax\n  int v7; // r14d\n  size_t v8; // r12\n  char *v9; // r14\n\n  v2 = s1;\n  v3 = strlen(s1);\n  v4 = v3;\n  if ( v3 )\n  {\n    v5 = v3;\n    v6 = strlen(s2);\n    v7 = v5 - v6;\n    if ( v7 < 0 )\n    {\n      return 0;\n    }\n    else\n    {\n      v8 = v6;\n      v4 = 0;\n      v9 = &s1[v7 + 1];\n      do\n        v4 += strncmp(v2++, s2, v8) == 0;\n      while ( v2 != v9 );\n    }\n  }\n  return v4;\n}",
        "ghidra_asm": "func0:\nENDBR64\nPUSH R14\nPUSH R13\nMOV R13,RSI\nPUSH R12\nPUSH RBP\nPUSH RBX\nMOV RBX,RDI\nCALL 0x00101080\nMOV EBP,EAX\nTEST EAX,EAX\nJZ 0x001012dd\nMOV RDI,R13\nMOV R14,RAX\nCALL 0x00101080\nSUB R14D,EAX\nJS 0x001012f0\nMOVSXD R14,R14D\nMOVSXD R12,EAX\nXOR EBP,EBP\nLEA R14,[RBX + R14*0x1 + 0x1]\nNOP word ptr [RAX + RAX*0x1]\nLAB_001012c0:\nMOV RDI,RBX\nMOV RDX,R12\nMOV RSI,R13\nCALL 0x00101070\nCMP EAX,0x1\nADC EBP,0x0\nADD RBX,0x1\nCMP RBX,R14\nJNZ 0x001012c0\nLAB_001012dd:\nPOP RBX\nMOV EAX,EBP\nPOP RBP\nPOP R12\nPOP R13\nPOP R14\nRET\nLAB_001012f0:\nXOR EBP,EBP\nJMP 0x001012dd",
        "ghidra_pseudo": "ulong func0(char *param_1,char *param_2)\n\n{\n  char *pcVar1;\n  size_t sVar2;\n  size_t sVar3;\n  ulong uVar4;\n  int iVar5;\n  \n  sVar2 = strlen(param_1);\n  uVar4 = sVar2 & 0xffffffff;\n  if ((int)sVar2 != 0) {\n    sVar3 = strlen(param_2);\n    iVar5 = (int)sVar2 - (int)sVar3;\n    if (iVar5 < 0) {\n      uVar4 = 0;\n    }\n    else {\n      uVar4 = 0;\n      pcVar1 = param_1 + (long)iVar5 + 1;\n      do {\n        iVar5 = strncmp(param_1,param_2,(long)(int)sVar3);\n        uVar4 = (ulong)((int)uVar4 + (uint)(iVar5 == 0));\n        param_1 = param_1 + 1;\n      } while (param_1 != pcVar1);\n    }\n  }\n  return uVar4;\n}",
        "optimized_func": "#include <string.h> // Required for strlen and strncmp\n#include <stddef.h> // Required for size_t\n\n// The original 'ulong' type is mapped to 'unsigned long' for standard C compatibility.\n// Parameters are made 'const char*' as the strings are read, not modified.\nunsigned long func0(const char *param_1, const char *param_2)\n{\n    size_t len1 = strlen(param_1);\n    size_t len2 = strlen(param_2);\n    unsigned long count = 0; // Corresponds to the original 'uVar4'\n\n    // The original code returns 0 if param_1 is an empty string.\n    // This check explicitly preserves that behavior.\n    if (len1 == 0) {\n        return 0;\n    }\n\n    // The original code proceeds only if param_1 is not shorter than param_2.\n    // If len1 < len2, the loop below will not execute, and 'count' (which is 0) will be returned,\n    // matching the original behavior (where 'uVar4' would be set to 0 and returned).\n    if (len1 >= len2) {\n        // This loop iterates through all possible starting positions of 'param_2' within 'param_1'.\n        // The loop runs from index 0 up to (len1 - len2), inclusive.\n        // This replaces the 'do-while' loop and eliminates the 'pcVar1' intermediate variable.\n        for (size_t i = 0; i <= len1 - len2; ++i) {\n            // Checks if the substring of 'param_1' starting at current 'i' matches 'param_2'.\n            // The result of strncmp (0 for match) is used directly, eliminating an 'iVar5' usage.\n            if (strncmp(param_1 + i, param_2, len2) == 0) {\n                count++; // Increments count if a match is found.\n            }\n        }\n    }\n\n    // The behavior for an empty 'param_2' (len2 == 0) and non-empty 'param_1' (len1 > 0)\n    // is preserved: 'count' will be 'len1 + 1'.\n    return count;\n}",
        "optimization_status": true
      }
      {
        "executable_name": "temp_executable_67",
        "functions": [
            {
                "f_name": "func0",
                "asm": "func0(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >):\nendbr64\npush   %r14\npxor   %xmm0,%xmm0\npush   %r13\npush   %r12\npush   %rbp\nmov    %rdi,%rbp\npush   %rbx\nsub    $0x20,%rsp\nmov    (%rdi),%r14\nmov    0x8(%rdi),%r12\nmov    %fs:0x28,%rax\nmov    %rax,0x18(%rsp)\nxor    %eax,%eax\nmovaps %xmm0,(%rsp)\nmovq   $0x0,0x10(%rsp)\nlea    (%r14,%r12,1),%r13\nmov    %r14,%rbx\ncmp    %r14,%r13\nje     16c4 <_Z5func0NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE+0x64>\nnopw   0x0(%rax,%rax,1)\nmovsbl (%rbx),%edi\nadd    $0x1,%rbx\ncallq  1180 <tolower@plt>\nmov    %al,-0x1(%rbx)\ncmp    %rbx,%r13\njne    16b0 <_Z5func0NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE+0x50>\nxor    %ebx,%ebx\nxor    %r9d,%r9d\nxor    %r10d,%r10d\nmov    %rsp,%r13\ntest   %r12,%r12\nje     176a <_Z5func0NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE+0x10a>\nmov    %r10,%rax\nadd    %rbx,%r14\nsub    %r9,%rax\nje     172b <_Z5func0NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE+0xcb>\nnopl   0x0(%rax,%rax,1)\nmovzbl (%r14),%r8d\nmov    %r9,%rdx\nlea    (%rax,%r9,1),%rdi\nxor    %ecx,%ecx\nmov    $0x1,%esi\nnopw   0x0(%rax,%rax,1)\ncmp    (%rdx),%r8b\ncmove  %esi,%ecx\nadd    $0x1,%rdx\ncmp    %rdx,%rdi\njne    1700 <_Z5func0NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE+0xa0>\ntest   %cl,%cl\nje     172b <_Z5func0NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE+0xcb>\nadd    $0x1,%rbx\ncmp    %r12,%rbx\njae    175a <_Z5func0NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE+0xfa>\nmov    0x0(%rbp),%r14\nmov    %r10,%rax\nadd    %rbx,%r14\nsub    %r9,%rax\njne    16e8 <_Z5func0NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE+0x88>\ncmp    %r10,0x10(%rsp)\nje     178a <_Z5func0NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE+0x12a>\nmovzbl (%r14),%eax\nadd    $0x1,%rbx\nmov    %al,(%r10)\nmov    0x8(%rsp),%rax\nmov    (%rsp),%r9\nlea    0x1(%rax),%r10\nmov    %r10,%rax\nmov    %r10,0x8(%rsp)\nsub    %r9,%rax\ncmp    %r12,%rbx\njb     171c <_Z5func0NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE+0xbc>\nmov    %eax,%r12d\ntest   %r9,%r9\nje     176a <_Z5func0NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE+0x10a>\nmov    %r9,%rdi\ncallq  1150 <_ZdlPv@plt>\nmov    0x18(%rsp),%rax\nxor    %fs:0x28,%rax\njne    17b0 <_Z5func0NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE+0x150>\nadd    $0x20,%rsp\nmov    %r12d,%eax\npop    %rbx\npop    %rbp\npop    %r12\npop    %r13\npop    %r14\nretq\nmov    %r14,%rdx\nmov    %r10,%rsi\nmov    %r13,%rdi\ncallq  17d0 <_ZNSt6vectorIcSaIcEE17_M_realloc_insertIJRKcEEEvN9__gnu_cxx17__normal_iteratorIPcS1_EEDpOT_>\nmov    0x8(%rsp),%r10\nmov    (%rsp),%r9\nmov    0x8(%rbp),%r12\nmov    %r10,%rax\nsub    %r9,%rax\njmpq   1713 <_Z5func0NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE+0xb3>\ncallq  1170 <__stack_chk_fail@plt>\nendbr64\nmov    %rax,%rbp\njmpq   11c0 <_Z5func0NSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE.cold>\nnopw   %cs:0x0(%rax,%rax,1)\nnopl   0x0(%rax,%rax,1)\n",
                "ghidra_code": "/* func0(std::string) */\n\nulong func0(long *param_1)\n\n{\n  bool bVar1;\n  int iVar2;\n  ulong uVar3;\n  char *pcVar4;\n  char *pcVar5;\n  char *pcVar6;\n  char *pcVar7;\n  ulong uVar8;\n  char *pcVar9;\n  ulong uVar10;\n  long in_FS_OFFSET;\n  int local_48 [16];\n  char *local_38;\n  long local_30;\n  \n  pcVar5 = (char *)*param_1;\n  local_30 = *(long *)(in_FS_OFFSET + 0x28);\n  local_48 = (int  [16])0x0;\n  local_38 = (char *)0x0;\n  pcVar7 = pcVar5 + param_1[1];\n  if (pcVar7 != pcVar5) {\n    do {\n      pcVar6 = pcVar5 + 1;\n      iVar2 = tolower((int)*pcVar5);\n      *pcVar5 = (char)iVar2;\n      pcVar5 = pcVar6;\n    } while (pcVar7 != pcVar6);\n    if (param_1[1] != 0) {\n      uVar8 = 0;\n      pcVar6 = (char *)0x0;\n      pcVar7 = (char *)0x0;\n      pcVar5 = (char *)0x0;\n      do {\n        uVar10 = (long)pcVar5 - (long)pcVar7;\n        if (pcVar5 == pcVar7) {\nLAB_00101778:\n          pcVar4 = (char *)(*param_1 + uVar8);\n          if (pcVar5 == pcVar6) {\n                    /* try { // try from 0010179a to 0010179e has its CatchHandler @ 001017be */\n            std::vector<char,std::allocator<char>>::_M_realloc_insert<char_const&>\n                      ((vector<char,std::allocator<char>> *)local_48,(__normal_iterator)pcVar5,\n                       pcVar4);\n            uVar10 = local_48._8_8_ - local_48._0_8_;\n            pcVar5 = (char *)local_48._8_8_;\n            pcVar7 = (char *)local_48._0_8_;\n            pcVar6 = local_38;\n          }\n          else {\n            pcVar9 = pcVar5 + 1;\n            *pcVar5 = *pcVar4;\n            local_48._8_8_ = pcVar9;\n            uVar10 = (long)pcVar9 - (long)pcVar7;\n            pcVar5 = pcVar9;\n          }\n        }\n        else {\n          uVar3 = 0;\n          bVar1 = false;\n          do {\n            if (*(char *)(*param_1 + uVar8) == pcVar7[uVar3]) {\n              bVar1 = true;\n            }\n            uVar3 = uVar3 + 1;\n          } while (uVar3 < uVar10);\n          if (!bVar1) goto LAB_00101778;\n        }\n        uVar8 = uVar8 + 1;\n      } while (uVar8 < (ulong)param_1[1]);\n      if (pcVar7 != (char *)0x0) {\n        operator_delete(pcVar7,(long)pcVar6 - (long)pcVar7);\n      }\n      uVar10 = uVar10 & 0xffffffff;\n      goto LAB_00101756;\n    }\n  }\n  uVar10 = 0;\nLAB_00101756:\n  if (local_30 != *(long *)(in_FS_OFFSET + 0x28)) {\n                    /* WARNING: Subroutine does not return */\n    __stack_chk_fail();\n  }\n  return uVar10;\n}",
                "sog_dot": "{\n  \"blocks\": [\n    {\n      \"instructions\": [\n        {\n          \"address\": \"00100000\", \n          \"ops\": [], \n          \"proto\": \"ENDBR64\", \n          \"mnemonic\": \"ENDBR64\"\n        }, \n        {\n          \"address\": \"00100004\", \n          \"ops\": [\n            \"RBP\"\n          ], \n          \"proto\": \"PUSH RBP\", \n          \"mnemonic\": \"PUSH\"\n        }, \n        {\n          \"address\": \"00100005\", \n          \"ops\": [\n            \"RBP\", \n            \"RSP\"\n          ], \n          \"proto\": \"MOV RBP,RSP\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100008\", \n          \"ops\": [\n            \"R12\"\n          ], \n          \"proto\": \"PUSH R12\", \n          \"mnemonic\": \"PUSH\"\n        }, \n        {\n          \"address\": \"0010000a\", \n          \"ops\": [\n            \"RBX\"\n          ], \n          \"proto\": \"PUSH RBX\", \n          \"mnemonic\": \"PUSH\"\n        }, \n        {\n          \"address\": \"0010000b\", \n          \"ops\": [\n            \"RSP\", \n            \"0x40\"\n          ], \n          \"proto\": \"SUB RSP,0x40\", \n          \"mnemonic\": \"SUB\"\n        }, \n        {\n          \"address\": \"0010000f\", \n          \"ops\": [\n            \"RBP\", \n            \"-0x48\", \n            \"RDI\"\n          ], \n          \"proto\": \"MOV qword ptr [RBP + -0x48],RDI\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100013\", \n          \"ops\": [\n            \"RAX\", \n            \"FS\", \n            \"0x28\"\n          ], \n          \"proto\": \"MOV RAX,qword ptr FS:[0x28]\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"0010001c\", \n          \"ops\": [\n            \"RBP\", \n            \"-0x18\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV qword ptr [RBP + -0x18],RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100020\", \n          \"ops\": [\n            \"EAX\", \n            \"EAX\"\n          ], \n          \"proto\": \"XOR EAX,EAX\", \n          \"mnemonic\": \"XOR\"\n        }, \n        {\n          \"address\": \"00100022\", \n          \"ops\": [\n            \"XMM0\", \n            \"XMM0\"\n          ], \n          \"proto\": \"PXOR XMM0,XMM0\", \n          \"mnemonic\": \"PXOR\"\n        }, \n        {\n          \"address\": \"00100026\", \n          \"ops\": [\n            \"RBP\", \n            \"-0x30\", \n            \"XMM0\"\n          ], \n          \"proto\": \"MOVAPS xmmword ptr [RBP + -0x30],XMM0\", \n          \"mnemonic\": \"MOVAPS\"\n        }, \n        {\n          \"address\": \"0010002a\", \n          \"ops\": [\n            \"RBP\", \n            \"-0x20\", \n            \"XMM0\"\n          ], \n          \"proto\": \"MOVQ qword ptr [RBP + -0x20],XMM0\", \n          \"mnemonic\": \"MOVQ\"\n        }, \n        {\n          \"address\": \"0010002f\", \n          \"ops\": [\n            \"RAX\", \n            \"RBP\", \n            \"-0x30\"\n          ], \n          \"proto\": \"LEA RAX,[RBP + -0x30]\", \n          \"mnemonic\": \"LEA\"\n        }, \n        {\n          \"address\": \"00100033\", \n          \"ops\": [\n            \"RDI\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV RDI,RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100036\", \n          \"ops\": [\n            \"00100212\"\n          ], \n          \"proto\": \"CALL 0x00100212\", \n          \"mnemonic\": \"CALL\"\n        }, \n        {\n          \"address\": \"0010003b\", \n          \"ops\": [\n            \"RAX\", \n            \"RBP\", \n            \"-0x48\"\n          ], \n          \"proto\": \"MOV RAX,qword ptr [RBP + -0x48]\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"0010003f\", \n          \"ops\": [\n            \"RDI\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV RDI,RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100042\", \n          \"ops\": [\n            \"00102000\"\n          ], \n          \"proto\": \"CALL 0x00102000\", \n          \"mnemonic\": \"CALL\"\n        }, \n        {\n          \"address\": \"00100047\", \n          \"ops\": [\n            \"R12\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV R12,RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"0010004a\", \n          \"ops\": [\n            \"RAX\", \n            \"RBP\", \n            \"-0x48\"\n          ], \n          \"proto\": \"MOV RAX,qword ptr [RBP + -0x48]\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"0010004e\", \n          \"ops\": [\n            \"RDI\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV RDI,RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100051\", \n          \"ops\": [\n            \"00102008\"\n          ], \n          \"proto\": \"CALL 0x00102008\", \n          \"mnemonic\": \"CALL\"\n        }, \n        {\n          \"address\": \"00100056\", \n          \"ops\": [\n            \"RBX\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV RBX,RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100059\", \n          \"ops\": [\n            \"RAX\", \n            \"RBP\", \n            \"-0x48\"\n          ], \n          \"proto\": \"MOV RAX,qword ptr [RBP + -0x48]\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"0010005d\", \n          \"ops\": [\n            \"RDI\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV RDI,RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100060\", \n          \"ops\": [\n            \"00102000\"\n          ], \n          \"proto\": \"CALL 0x00102000\", \n          \"mnemonic\": \"CALL\"\n        }, \n        {\n          \"address\": \"00100065\", \n          \"ops\": [\n            \"RDX\", \n            \"0x102010\"\n          ], \n          \"proto\": \"LEA RDX,[0x102010]\", \n          \"mnemonic\": \"LEA\"\n        }, \n        {\n          \"address\": \"0010006c\", \n          \"ops\": [\n            \"RCX\", \n            \"RDX\"\n          ], \n          \"proto\": \"MOV RCX,RDX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"0010006f\", \n          \"ops\": [\n            \"RDX\", \n            \"R12\"\n          ], \n          \"proto\": \"MOV RDX,R12\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100072\", \n          \"ops\": [\n            \"RSI\", \n            \"RBX\"\n          ], \n          \"proto\": \"MOV RSI,RBX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100075\", \n          \"ops\": [\n            \"RDI\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV RDI,RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100078\", \n          \"ops\": [\n            \"0010031c\"\n          ], \n          \"proto\": \"CALL 0x0010031c\", \n          \"mnemonic\": \"CALL\"\n        }, \n        {\n          \"address\": \"0010007d\", \n          \"ops\": [\n            \"RBP\", \n            \"-0x38\", \n            \"0x0\"\n          ], \n          \"proto\": \"MOV dword ptr [RBP + -0x38],0x0\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100084\", \n          \"ops\": [\n            \"00100126\"\n          ], \n          \"proto\": \"JMP 0x00100126\", \n          \"mnemonic\": \"JMP\"\n        }\n      ], \n      \"start\": \"00100000\", \n      \"id\": \"B0\"\n    }, \n    {\n      \"instructions\": [\n        {\n          \"address\": \"00100089\", \n          \"ops\": [\n            \"RBP\", \n            \"-0x39\", \n            \"0x0\"\n          ], \n          \"proto\": \"MOV byte ptr [RBP + -0x39],0x0\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"0010008d\", \n          \"ops\": [\n            \"RBP\", \n            \"-0x34\", \n            \"0x0\"\n          ], \n          \"proto\": \"MOV dword ptr [RBP + -0x34],0x0\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100094\", \n          \"ops\": [\n            \"001000d7\"\n          ], \n          \"proto\": \"JMP 0x001000d7\", \n          \"mnemonic\": \"JMP\"\n        }\n      ], \n      \"start\": \"00100089\", \n      \"id\": \"B1\"\n    }, \n    {\n      \"instructions\": [\n        {\n          \"address\": \"00100096\", \n          \"ops\": [\n            \"EAX\", \n            \"RBP\", \n            \"-0x34\"\n          ], \n          \"proto\": \"MOV EAX,dword ptr [RBP + -0x34]\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100099\", \n          \"ops\": [\n            \"RDX\", \n            \"EAX\"\n          ], \n          \"proto\": \"MOVSXD RDX,EAX\", \n          \"mnemonic\": \"MOVSXD\"\n        }, \n        {\n          \"address\": \"0010009c\", \n          \"ops\": [\n            \"RAX\", \n            \"RBP\", \n            \"-0x30\"\n          ], \n          \"proto\": \"LEA RAX,[RBP + -0x30]\", \n          \"mnemonic\": \"LEA\"\n        }, \n        {\n          \"address\": \"001000a0\", \n          \"ops\": [\n            \"RSI\", \n            \"RDX\"\n          ], \n          \"proto\": \"MOV RSI,RDX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"001000a3\", \n          \"ops\": [\n            \"RDI\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV RDI,RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"001000a6\", \n          \"ops\": [\n            \"001003c2\"\n          ], \n          \"proto\": \"CALL 0x001003c2\", \n          \"mnemonic\": \"CALL\"\n        }, \n        {\n          \"address\": \"001000ab\", \n          \"ops\": [\n            \"EBX\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOVZX EBX,byte ptr [RAX]\", \n          \"mnemonic\": \"MOVZX\"\n        }, \n        {\n          \"address\": \"001000ae\", \n          \"ops\": [\n            \"EAX\", \n            \"RBP\", \n            \"-0x38\"\n          ], \n          \"proto\": \"MOV EAX,dword ptr [RBP + -0x38]\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"001000b1\", \n          \"ops\": [\n            \"RDX\", \n            \"EAX\"\n          ], \n          \"proto\": \"MOVSXD RDX,EAX\", \n          \"mnemonic\": \"MOVSXD\"\n        }, \n        {\n          \"address\": \"001000b4\", \n          \"ops\": [\n            \"RAX\", \n            \"RBP\", \n            \"-0x48\"\n          ], \n          \"proto\": \"MOV RAX,qword ptr [RBP + -0x48]\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"001000b8\", \n          \"ops\": [\n            \"RSI\", \n            \"RDX\"\n          ], \n          \"proto\": \"MOV RSI,RDX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"001000bb\", \n          \"ops\": [\n            \"RDI\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV RDI,RAX\", \n          \"mnemonic\": \"MOV\"\n        }\n      ], \n      \"start\": \"00100096\", \n      \"id\": \"B2\"\n    }, \n    {\n      \"instructions\": [\n        {\n          \"address\": \"001000be\", \n          \"ops\": [\n            \"00102018\"\n          ], \n          \"proto\": \"CALL 0x00102018\", \n          \"mnemonic\": \"CALL\"\n        }, \n        {\n          \"address\": \"001000c3\", \n          \"ops\": [\n            \"EAX\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOVZX EAX,byte ptr [RAX]\", \n          \"mnemonic\": \"MOVZX\"\n        }, \n        {\n          \"address\": \"001000c6\", \n          \"ops\": [\n            \"BL\", \n            \"AL\"\n          ], \n          \"proto\": \"CMP BL,AL\", \n          \"mnemonic\": \"CMP\"\n        }, \n        {\n          \"address\": \"001000c8\", \n          \"ops\": [\n            \"AL\"\n          ], \n          \"proto\": \"SETZ AL\", \n          \"mnemonic\": \"SETZ\"\n        }, \n        {\n          \"address\": \"001000cb\", \n          \"ops\": [\n            \"AL\", \n            \"AL\"\n          ], \n          \"proto\": \"TEST AL,AL\", \n          \"mnemonic\": \"TEST\"\n        }, \n        {\n          \"address\": \"001000cd\", \n          \"ops\": [\n            \"001000d3\"\n          ], \n          \"proto\": \"JZ 0x001000d3\", \n          \"mnemonic\": \"JZ\"\n        }\n      ], \n      \"start\": \"001000be\", \n      \"id\": \"B3\"\n    }, \n    {\n      \"instructions\": [\n        {\n          \"address\": \"001000cf\", \n          \"ops\": [\n            \"RBP\", \n            \"-0x39\", \n            \"0x1\"\n          ], \n          \"proto\": \"MOV byte ptr [RBP + -0x39],0x1\", \n          \"mnemonic\": \"MOV\"\n        }\n      ], \n      \"start\": \"001000cf\", \n      \"id\": \"B4\"\n    }, \n    {\n      \"instructions\": [\n        {\n          \"address\": \"001000d3\", \n          \"ops\": [\n            \"RBP\", \n            \"-0x34\", \n            \"0x1\"\n          ], \n          \"proto\": \"ADD dword ptr [RBP + -0x34],0x1\", \n          \"mnemonic\": \"ADD\"\n        }\n      ], \n      \"start\": \"001000d3\", \n      \"id\": \"B5\"\n    }, \n    {\n      \"instructions\": [\n        {\n          \"address\": \"001000d7\", \n          \"ops\": [\n            \"EAX\", \n            \"RBP\", \n            \"-0x34\"\n          ], \n          \"proto\": \"MOV EAX,dword ptr [RBP + -0x34]\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"001000da\", \n          \"ops\": [\n            \"RBX\", \n            \"EAX\"\n          ], \n          \"proto\": \"MOVSXD RBX,EAX\", \n          \"mnemonic\": \"MOVSXD\"\n        }, \n        {\n          \"address\": \"001000dd\", \n          \"ops\": [\n            \"RAX\", \n            \"RBP\", \n            \"-0x30\"\n          ], \n          \"proto\": \"LEA RAX,[RBP + -0x30]\", \n          \"mnemonic\": \"LEA\"\n        }, \n        {\n          \"address\": \"001000e1\", \n          \"ops\": [\n            \"RDI\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV RDI,RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"001000e4\", \n          \"ops\": [\n            \"0010039e\"\n          ], \n          \"proto\": \"CALL 0x0010039e\", \n          \"mnemonic\": \"CALL\"\n        }, \n        {\n          \"address\": \"001000e9\", \n          \"ops\": [\n            \"RBX\", \n            \"RAX\"\n          ], \n          \"proto\": \"CMP RBX,RAX\", \n          \"mnemonic\": \"CMP\"\n        }, \n        {\n          \"address\": \"001000ec\", \n          \"ops\": [\n            \"AL\"\n          ], \n          \"proto\": \"SETC AL\", \n          \"mnemonic\": \"SETC\"\n        }, \n        {\n          \"address\": \"001000ef\", \n          \"ops\": [\n            \"AL\", \n            \"AL\"\n          ], \n          \"proto\": \"TEST AL,AL\", \n          \"mnemonic\": \"TEST\"\n        }, \n        {\n          \"address\": \"001000f1\", \n          \"ops\": [\n            \"00100096\"\n          ], \n          \"proto\": \"JNZ 0x00100096\", \n          \"mnemonic\": \"JNZ\"\n        }\n      ], \n      \"start\": \"001000d7\", \n      \"id\": \"B6\"\n    }, \n    {\n      \"instructions\": [\n        {\n          \"address\": \"001000f3\", \n          \"ops\": [\n            \"EAX\", \n            \"RBP\", \n            \"-0x39\"\n          ], \n          \"proto\": \"MOVZX EAX,byte ptr [RBP + -0x39]\", \n          \"mnemonic\": \"MOVZX\"\n        }, \n        {\n          \"address\": \"001000f7\", \n          \"ops\": [\n            \"EAX\", \n            \"EAX\"\n          ], \n          \"proto\": \"TEST EAX,EAX\", \n          \"mnemonic\": \"TEST\"\n        }, \n        {\n          \"address\": \"001000f9\", \n          \"ops\": [\n            \"00100122\"\n          ], \n          \"proto\": \"JNZ 0x00100122\", \n          \"mnemonic\": \"JNZ\"\n        }\n      ], \n      \"start\": \"001000f3\", \n      \"id\": \"B7\"\n    }, \n    {\n      \"instructions\": [\n        {\n          \"address\": \"001000fb\", \n          \"ops\": [\n            \"EAX\", \n            \"RBP\", \n            \"-0x38\"\n          ], \n          \"proto\": \"MOV EAX,dword ptr [RBP + -0x38]\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"001000fe\", \n          \"ops\": [\n            \"RDX\", \n            \"EAX\"\n          ], \n          \"proto\": \"MOVSXD RDX,EAX\", \n          \"mnemonic\": \"MOVSXD\"\n        }, \n        {\n          \"address\": \"00100101\", \n          \"ops\": [\n            \"RAX\", \n            \"RBP\", \n            \"-0x48\"\n          ], \n          \"proto\": \"MOV RAX,qword ptr [RBP + -0x48]\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100105\", \n          \"ops\": [\n            \"RSI\", \n            \"RDX\"\n          ], \n          \"proto\": \"MOV RSI,RDX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100108\", \n          \"ops\": [\n            \"RDI\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV RDI,RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"0010010b\", \n          \"ops\": [\n            \"00102018\"\n          ], \n          \"proto\": \"CALL 0x00102018\", \n          \"mnemonic\": \"CALL\"\n        }, \n        {\n          \"address\": \"00100110\", \n          \"ops\": [\n            \"RDX\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV RDX,RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100113\", \n          \"ops\": [\n            \"RAX\", \n            \"RBP\", \n            \"-0x30\"\n          ], \n          \"proto\": \"LEA RAX,[RBP + -0x30]\", \n          \"mnemonic\": \"LEA\"\n        }, \n        {\n          \"address\": \"00100117\", \n          \"ops\": [\n            \"RSI\", \n            \"RDX\"\n          ], \n          \"proto\": \"MOV RSI,RDX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"0010011a\", \n          \"ops\": [\n            \"RDI\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV RDI,RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"0010011d\", \n          \"ops\": [\n            \"001003e2\"\n          ], \n          \"proto\": \"CALL 0x001003e2\", \n          \"mnemonic\": \"CALL\"\n        }\n      ], \n      \"start\": \"001000fb\", \n      \"id\": \"B8\"\n    }, \n    {\n      \"instructions\": [\n        {\n          \"address\": \"00100122\", \n          \"ops\": [\n            \"RBP\", \n            \"-0x38\", \n            \"0x1\"\n          ], \n          \"proto\": \"ADD dword ptr [RBP + -0x38],0x1\", \n          \"mnemonic\": \"ADD\"\n        }\n      ], \n      \"start\": \"00100122\", \n      \"id\": \"B9\"\n    }, \n    {\n      \"instructions\": [\n        {\n          \"address\": \"00100126\", \n          \"ops\": [\n            \"EAX\", \n            \"RBP\", \n            \"-0x38\"\n          ], \n          \"proto\": \"MOV EAX,dword ptr [RBP + -0x38]\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100129\", \n          \"ops\": [\n            \"RBX\", \n            \"EAX\"\n          ], \n          \"proto\": \"MOVSXD RBX,EAX\", \n          \"mnemonic\": \"MOVSXD\"\n        }, \n        {\n          \"address\": \"0010012c\", \n          \"ops\": [\n            \"RAX\", \n            \"RBP\", \n            \"-0x48\"\n          ], \n          \"proto\": \"MOV RAX,qword ptr [RBP + -0x48]\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100130\", \n          \"ops\": [\n            \"RDI\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV RDI,RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100133\", \n          \"ops\": [\n            \"00102020\"\n          ], \n          \"proto\": \"CALL 0x00102020\", \n          \"mnemonic\": \"CALL\"\n        }, \n        {\n          \"address\": \"00100138\", \n          \"ops\": [\n            \"RBX\", \n            \"RAX\"\n          ], \n          \"proto\": \"CMP RBX,RAX\", \n          \"mnemonic\": \"CMP\"\n        }, \n        {\n          \"address\": \"0010013b\", \n          \"ops\": [\n            \"AL\"\n          ], \n          \"proto\": \"SETC AL\", \n          \"mnemonic\": \"SETC\"\n        }, \n        {\n          \"address\": \"0010013e\", \n          \"ops\": [\n            \"AL\", \n            \"AL\"\n          ], \n          \"proto\": \"TEST AL,AL\", \n          \"mnemonic\": \"TEST\"\n        }, \n        {\n          \"address\": \"00100140\", \n          \"ops\": [\n            \"00100089\"\n          ], \n          \"proto\": \"JNZ 0x00100089\", \n          \"mnemonic\": \"JNZ\"\n        }\n      ], \n      \"start\": \"00100126\", \n      \"id\": \"B10\"\n    }, \n    {\n      \"instructions\": [\n        {\n          \"address\": \"00100146\", \n          \"ops\": [\n            \"RAX\", \n            \"RBP\", \n            \"-0x30\"\n          ], \n          \"proto\": \"LEA RAX,[RBP + -0x30]\", \n          \"mnemonic\": \"LEA\"\n        }, \n        {\n          \"address\": \"0010014a\", \n          \"ops\": [\n            \"RDI\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV RDI,RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"0010014d\", \n          \"ops\": [\n            \"0010039e\"\n          ], \n          \"proto\": \"CALL 0x0010039e\", \n          \"mnemonic\": \"CALL\"\n        }, \n        {\n          \"address\": \"00100152\", \n          \"ops\": [\n            \"EBX\", \n            \"EAX\"\n          ], \n          \"proto\": \"MOV EBX,EAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100154\", \n          \"ops\": [\n            \"RAX\", \n            \"RBP\", \n            \"-0x30\"\n          ], \n          \"proto\": \"LEA RAX,[RBP + -0x30]\", \n          \"mnemonic\": \"LEA\"\n        }, \n        {\n          \"address\": \"00100158\", \n          \"ops\": [\n            \"RDI\", \n            \"RAX\"\n          ], \n          \"proto\": \"MOV RDI,RAX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"0010015b\", \n          \"ops\": [\n            \"001002c2\"\n          ], \n          \"proto\": \"CALL 0x001002c2\", \n          \"mnemonic\": \"CALL\"\n        }, \n        {\n          \"address\": \"00100160\", \n          \"ops\": [\n            \"EAX\", \n            \"EBX\"\n          ], \n          \"proto\": \"MOV EAX,EBX\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100162\", \n          \"ops\": [\n            \"RDX\", \n            \"RBP\", \n            \"-0x18\"\n          ], \n          \"proto\": \"MOV RDX,qword ptr [RBP + -0x18]\", \n          \"mnemonic\": \"MOV\"\n        }, \n        {\n          \"address\": \"00100166\", \n          \"ops\": [\n            \"RDX\", \n            \"FS\", \n            \"0x28\"\n          ], \n          \"proto\": \"SUB RDX,qword ptr FS:[0x28]\", \n          \"mnemonic\": \"SUB\"\n        }, \n        {\n          \"address\": \"0010016f\", \n          \"ops\": [\n            \"001001aa\"\n          ], \n          \"proto\": \"JZ 0x001001aa\", \n          \"mnemonic\": \"JZ\"\n        }\n      ], \n      \"start\": \"00100146\", \n      \"id\": \"B11\"\n    }, \n    {\n      \"instructions\": [\n        {\n          \"address\": \"00100171\", \n          \"ops\": [\n            \"001001a5\"\n          ], \n          \"proto\": \"JMP 0x001001a5\", \n          \"mnemonic\": \"JMP\"\n        }\n      ], \n      \"start\": \"00100171\", \n      \"id\": \"B12\"\n    }, \n    {\n      \"instructions\": [\n        {\n          \"address\": \"001001a5\", \n          \"ops\": [\n            \"00102028\"\n          ], \n          \"proto\": \"CALL 0x00102028\", \n          \"mnemonic\": \"CALL\"\n        }\n      ], \n      \"start\": \"001001a5\", \n      \"id\": \"B13\"\n    }, \n    {\n      \"instructions\": [\n        {\n          \"address\": \"001001aa\", \n          \"ops\": [\n            \"RSP\", \n            \"0x40\"\n          ], \n          \"proto\": \"ADD RSP,0x40\", \n          \"mnemonic\": \"ADD\"\n        }, \n        {\n          \"address\": \"001001ae\", \n          \"ops\": [\n            \"RBX\"\n          ], \n          \"proto\": \"POP RBX\", \n          \"mnemonic\": \"POP\"\n        }, \n        {\n          \"address\": \"001001af\", \n          \"ops\": [\n            \"R12\"\n          ], \n          \"proto\": \"POP R12\", \n          \"mnemonic\": \"POP\"\n        }, \n        {\n          \"address\": \"001001b1\", \n          \"ops\": [\n            \"RBP\"\n          ], \n          \"proto\": \"POP RBP\", \n          \"mnemonic\": \"POP\"\n        }, \n        {\n          \"address\": \"001001b2\", \n          \"ops\": [], \n          \"proto\": \"RET\", \n          \"mnemonic\": \"RET\"\n        }\n      ], \n      \"start\": \"001001aa\", \n      \"id\": \"B14\"\n    }\n  ], \n  \"edges\": [\n    {\n      \"dst\": \"B10\", \n      \"src\": \"B0\", \n      \"type\": \"UNCONDITIONAL_JUMP\"\n    }, \n    {\n      \"dst\": \"B6\", \n      \"src\": \"B1\", \n      \"type\": \"UNCONDITIONAL_JUMP\"\n    }, \n    {\n      \"dst\": \"B3\", \n      \"src\": \"B2\", \n      \"type\": \"FALL_THROUGH\"\n    }, \n    {\n      \"dst\": \"B5\", \n      \"src\": \"B3\", \n      \"type\": \"CONDITIONAL_JUMP\"\n    }, \n    {\n      \"dst\": \"B4\", \n      \"src\": \"B3\", \n      \"type\": \"FALL_THROUGH\"\n    }, \n    {\n      \"dst\": \"B5\", \n      \"src\": \"B4\", \n      \"type\": \"FALL_THROUGH\"\n    }, \n    {\n      \"dst\": \"B6\", \n      \"src\": \"B5\", \n      \"type\": \"FALL_THROUGH\"\n    }, \n    {\n      \"dst\": \"B2\", \n      \"src\": \"B6\", \n      \"type\": \"CONDITIONAL_JUMP\"\n    }, \n    {\n      \"dst\": \"B7\", \n      \"src\": \"B6\", \n      \"type\": \"FALL_THROUGH\"\n    }, \n    {\n      \"dst\": \"B9\", \n      \"src\": \"B7\", \n      \"type\": \"CONDITIONAL_JUMP\"\n    }, \n    {\n      \"dst\": \"B8\", \n      \"src\": \"B7\", \n      \"type\": \"FALL_THROUGH\"\n    }, \n    {\n      \"dst\": \"B9\", \n      \"src\": \"B8\", \n      \"type\": \"FALL_THROUGH\"\n    }, \n    {\n      \"dst\": \"B10\", \n      \"src\": \"B9\", \n      \"type\": \"FALL_THROUGH\"\n    }, \n    {\n      \"dst\": \"B1\", \n      \"src\": \"B10\", \n      \"type\": \"CONDITIONAL_JUMP\"\n    }, \n    {\n      \"dst\": \"B11\", \n      \"src\": \"B10\", \n      \"type\": \"FALL_THROUGH\"\n    }, \n    {\n      \"dst\": \"B14\", \n      \"src\": \"B11\", \n      \"type\": \"CONDITIONAL_JUMP\"\n    }, \n    {\n      \"dst\": \"B12\", \n      \"src\": \"B11\", \n      \"type\": \"FALL_THROUGH\"\n    }, \n    {\n      \"dst\": \"B13\", \n      \"src\": \"B12\", \n      \"type\": \"UNCONDITIONAL_JUMP\"\n    }\n  ], \n  \"entry\": \"00100000\", \n  \"function_name\": \"func0\"\n}",
                "callers": [],
                "callees": [
                    "size",
                    "operator[]",
                    "__stack_chk_fail",
                    "push_back",
                    "~vector",
                    "end",
                    "begin",
                    "size",
                    "operator[]",
                    "transform<__gnu_cxx::__normal_iterator<char*,std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>>,__gnu_cxx::__normal_iterator<char*,std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>>,int(*)(int)noexcept>",
                    "vector"
                ],
                "function_summary": "{\"purpose\":\"This function accepts a mutable C++ std::string reference, converts all alphabetic characters to lowercase, then iteratively removes any repeated character occurrences from the resulting string. It uses an auxiliary vector to rebuild the string without duplicates and returns the new length of the processed string as a 64\u2011bit unsigned integer.\",\"return_type\":\"uint64_t\",\"args\":[{\"name\":\"str\",\"type\":\"std::string*\"}]}",
                "optimization_status": true,
                "optimized_code": "#include <string>\n#include <cctype>\n#include <cstdint>\n\nuint64_t func0(std::string* str)\n{\n    if (!str) return 0;\n\n    std::string& s = *str;\n\n    // convert to lowercase\n    for (char& ch : s) {\n        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));\n    }\n\n    // remove duplicates, preserving order\n    std::string result;\n    result.reserve(s.size());\n    for (char ch : s) {\n        if (result.find(ch) == std::string::npos) {\n            result.push_back(ch);\n        }\n    }\n\n    s = std::move(result);\n    return static_cast<uint64_t>(s.size());\n}"
            }
        ],
        "callgraph": {
            "__relocate_a_1<char,char>": [
                "memmove"
            ],
            "deallocate": [
                "operator.delete"
            ],
            "push_back": [
                "operator.new",
                "forward<char_const&>",
                "end",
                "_M_realloc_insert<char_const&>"
            ],
            "_M_check_len": [
                "__throw_length_error",
                "size",
                "__stack_chk_fail",
                "max<unsigned_long>",
                "max_size"
            ],
            "operator-": [
                "base"
            ],
            "_S_relocate": [
                "__relocate_a<char*,char*,std::allocator<char>>"
            ],
            "operator!=": [
                "base"
            ],
            "__relocate_a<char*,char*,std::allocator<char>>": [
                "__niter_base<char*>",
                "__relocate_a_1<char,char>"
            ],
            "_S_max_size": [
                "__stack_chk_fail",
                "min<unsigned_long>"
            ],
            "_M_deallocate": [
                "deallocate"
            ],
            "_M_allocate": [
                "allocate"
            ],
            "max_size": [
                "_S_max_size",
                "_M_get_Tp_allocator"
            ],
            "allocate": [
                "operator.new",
                "__throw_bad_alloc"
            ],
            "func0": [
                "size",
                "operator[]",
                "__stack_chk_fail",
                "push_back",
                "~vector",
                "end",
                "begin",
                "size",
                "operator[]",
                "transform<__gnu_cxx::__normal_iterator<char*,std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>>,__gnu_cxx::__normal_iterator<char*,std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>>,int(*)(int)noexcept>",
                "vector"
            ],
            "_M_realloc_insert<char_const&>": [
                "base",
                "operator.new",
                "forward<char_const&>",
                "_M_get_Tp_allocator",
                "begin",
                "__stack_chk_fail",
                "_M_allocate",
                "_M_check_len",
                "_M_deallocate",
                "operator-",
                "_S_relocate"
            ],
            "transform<__gnu_cxx::__normal_iterator<char*,std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>>,__gnu_cxx::__normal_iterator<char*,std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>>,int(*)(int)noexcept>": [
                "operator*",
                "operator++",
                "operator!="
            ],
            "_Destroy<char*>": [
                "__destroy<char*>"
            ]
        },
        "index": 67,
        "language": "cpp"
        
      }
  """
  
  # Load the JSON file
  with open(corpus_file, "r") as f:
    corpus = json.load(f)
  with open(output_file, "r") as out_f:
    output = json.load(out_f)
    
  for data in output:
    corpus_index = data["index"]
    optimized_code = ""
    c_include = ""
    for function in data["functions"]:
      if function["f_name"] == "func0" and function["optimization_status"] == True:
        optimized_code = function["optimized_code"]
        break
    for data in corpus:
      if data["index"] == corpus_index:
        test_code = data["test"]
        c_include += data["func_dep"] + "\n"
        break
    
    # get the includes from data["optimized_func"] and data["test"]
    print(f"Processing index: {corpus_index}")
    c_optimized = optimized_code
    c_test = test_code
    if optimized_code != "":
      total += 1
      
    for line in optimized_code.splitlines():
      if "include" in line:
        c_include += line + "\n"
        c_optimized = c_optimized.replace(line,"")
    for line in test_code.splitlines():
      if "include" in line:
        c_include += line + "\n"
        c_test = c_test.replace(line,"")
    # add the 'using namespace std'
    if data["language"] == "cpp":
      c_include += "using namespace std;\n"
        
    original_c_code = c_include + "\n" + c_optimized + "\n" + c_test
    #print(f"ORIGINAL C CODE : {original_c_code}")
    language = data["language"]
    
    with tempfile.TemporaryDirectory() as temp_dir:
      temp_dir_path = Path(temp_dir)
      c_file_path = temp_dir_path / f"temp_code.{'cpp' if language == 'cpp' else 'c'}"
      with open(c_file_path, "w") as f:
        f.write(original_c_code)
      
      #print(original_c_code)
      
      # attempt to compile and execute the original code
      compiled, executed, runtime_message = compile_and_execute(c_file_path, language)
      if not compiled:
        print("Compilation Error : ", runtime_message)
        c_fail += 1
      elif compiled and executed:
        ce_success += 1
        print(f"EXE Rate: {ce_success}/{total} ({ce_success/total*100:.2f}%)")
      else:
        e_fail += 1
        print("Error : ", runtime_message)
        
        
    print(f"Compilation failures: {c_fail}\n Execution failures: {e_fail}\n Successful executions: {ce_success} out of {total}\n")
      
    
  return ce_success, total
    
    
def main():
  """
  Main function to process all JSON files in the corpus root directory.
  """
  
  corpus_file = corpus_path / "humaneval-decompile.json"
  output_file = output_path / "batched_enriched_humaneval_decompile.json"
  
  success, total = process_json_file(corpus_file, output_file)
        


if __name__ == "__main__":
  main()