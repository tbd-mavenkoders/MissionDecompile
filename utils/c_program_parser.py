import re
from pathlib import Path
from typing import Dict


def create_ghidra_dict(function_code: str) -> Dict[str, str]:
    keywords = {
        'if', 'for', 'while', 'switch', 'else', 'return', 'sizeof', 'typedef',
        'struct', 'union', 'enum', 'case', 'default', 'do', 'goto', 'break', 'continue'
    }
    code = function_code
    function_map: Dict[str, str] = {}

    # Mask comments, string and char literals with spaces to preserve offsets
    pattern_mask = re.compile(r"""//.*?$|/\*.*?\*/|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'""", re.DOTALL | re.MULTILINE)
    def _mask(m):
        return ' ' * (m.end() - m.start())
    masked = re.sub(pattern_mask, _mask, code)

    # Regex to find an identifier immediately followed by '(' then ')' and '{'
    header_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{)]*\)\s*\{", re.MULTILINE)

    for m in header_re.finditer(masked):
        name = m.group(1)
        # skip C keywords
        if name in keywords:
            continue
        # Start at the function-name match; then expand backwards to include
        # the return type and any preceding specifiers (static, inline, etc.).
        start_idx = m.start()
        # Find start of the line containing the match
        line_start = code.rfind('\n', 0, start_idx)
        if line_start == -1:
            line_start = 0
        else:
            line_start = line_start + 1

        # Look back up to 3 previous lines and include them if they look like
        # part of the function signature (not blank and not ending with ';' or '}').
        max_prev_lines = 3
        prev_line_count = 0
        while prev_line_count < max_prev_lines:
            if line_start == 0:
                break
            prev_line_end = line_start - 1
            prev_line_start = code.rfind('\n', 0, prev_line_end)
            if prev_line_start == -1:
                prev_line_start = 0
            else:
                prev_line_start = prev_line_start + 1
            prev_line_text = code[prev_line_start:prev_line_end + 1].strip()
            if prev_line_text == '' or prev_line_text.endswith(';') or prev_line_text.endswith('}'):
                break
            # include this previous line
            line_start = prev_line_start
            prev_line_count += 1

        start_idx = line_start
        brace_pos = masked.find('{', m.end() - 1)
        if brace_pos == -1:
            continue
        depth = 0
        i = brace_pos
        end_idx = None
        N = len(masked)
        while i < N:
            ch = masked[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end_idx = i
                    break
            i += 1

        if end_idx is None:
            continue
        func_text = code[start_idx:end_idx + 1]
        if name not in function_map:
            function_map[name] = func_text

    return function_map