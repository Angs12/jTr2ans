#!/usr/bin/env python3
"""
r2_process.py — radare2 replacement for process.py (IDAPython).
Extracts function features (CFG + per-block assembly) from a stripped binary
and saves them in the same pickle format as the IDA-based pipeline.

Usage:
    python3 r2_process.py <stripped_binary> <non_stripped_path> <output_dir>

Produces: <output_dir>/<binary_name>_extract.pkl
"""
import r2pipe
import json
import networkx as nx
import pickle
import os
import sys
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from util.base import Binarybase

# ── r2 configuration ──────────────────────────────────────────────────────────
R2_CFG = {
    "asm.syntax": "jz",
    "asm.bytes": "false",
    "asm.lines": "false",
    "asm.functions": "false",
    "asm.emu": "false",
    "asm.comments": "false",
    "asm.labels": "false",
    "anal.vars": "true",
    "asm.var": "true",
    "asm.sub.var": "true",
    "asm.sub.varonly": "false",
    "anal.jmp.indir": "true",
    "anal.datarefs": "true",
    "anal.refstr": "true",
    "anal.strings": "true",
}

MNEMONIC_MAP = {
    "jae":   "jnb",
    "cmove": "cmovz",
    "ret":   "retn",
    "sete":  "setz",
    "setne": "setnz",
    "seta":  "setnbe",
    "movabs": "mov",
}


def normalize_asm(asm_line: str) -> str:
    """Normalize an r2 disassembly line to match IDA's parse_asm conventions."""
    asm_line = asm_line.strip()
    if not asm_line:
        return asm_line

    if asm_line == "invalid" or asm_line.startswith("invalid "):
        return ""

    if asm_line.startswith("notrack "):
        asm_line = asm_line[len("notrack "):]

    parts = asm_line.split(None, 1)
    op = parts[0] if parts else ""
    rest = parts[1] if len(parts) > 1 else ""

    op = MNEMONIC_MAP.get(op, op)

    if not rest:
        return op

    is_jump = op in {
        "jmp", "jz", "jnz", "ja", "jb", "jae", "jbe",
        "jg", "jl", "jge", "jle", "jo", "jno", "js", "jns",
        "jp", "jnp", "jpe", "jpo", "jcxz", "jecxz", "jrcxz",
    } or op == "call"

    line = f"{op} {rest}"

    # 1a. Convert r2's "canary" to standard variable name
    line = re.sub(r'\[(rbp|rbx|rsp|r12|r13)\s*-\s*canary\]', r'[\1-var_8h]', line)

    # 1b. Strip spaces inside brackets: [rax + 8] → [rax+8]
    line = re.sub(r'\[([^\]]+)\]', lambda m: '[' + m.group(1).replace(' ', '') + ']', line)

    # 1c. Convert indirect call format to match IDA's cs:xxx
    #     call qword [reloc.xxx] / [sym.xxx] / [method.xxx] → call cs:xxx
    if op == "call":
        line = re.sub(r'\bqword\s*\[\w+\.([^\]]+)\]', r'cs:\1', line)

    # 2. Hex constants: 0xHEX → sub_HEX (call) / loc_HEX (jump) or HEXh (constants)
    def _hex_repl(m):
        digits = m.group(1).upper()
        if op == "call":
            return f"sub_{digits}"
        return f"loc_{digits}" if is_jump else f"{digits}h"

    line = re.sub(r'\b0x([0-9a-fA-F]+)\b', _hex_repl, line)

    return line


def extract_function(r2, func_addr: int) -> dict:
    """Extract CFG + per-block assembly for a single function."""
    r2.cmd(f"s {hex(func_addr)}")
    r2.cmd("af")
    r2.cmd("afva")
    r2.cmd("afb")
    bb_list = json.loads(r2.cmd("afbj"))

    G = nx.DiGraph()
    block_addrs = {bb["addr"] for bb in bb_list}

    for bb in bb_list:
        addr = bb["addr"]
        instr_addrs = bb.get("instrs", [])

        asm_lines = []
        for ia in instr_addrs:
            if aoj := json.loads(r2.cmd(f"aoj 1 @ {hex(ia)}")):
                entry = aoj[0]
                if entry["mnemonic"] == "call":
                    opcode = entry.get("opcode", "")
                    # Direct calls: use opcode → sub_xxx (matches IDA's default)
                    # Indirect calls (contain [...]): use disasm → can normalize to cs:xxx
                    if "[" in opcode:
                        line = entry.get("disasm", opcode)
                    else:
                        line = opcode
                else:
                    r2.cmd(f"s {hex(ia)}")
                    line = r2.cmd("pi 1").strip()
            else:
                line = ""
            if not line:
                continue
            asm_lines.append(normalize_asm(line))

        G.add_node(addr, asm=asm_lines)

        jump = bb.get("jump", 0)
        fail = bb.get("fail", 0)
        if jump and jump in block_addrs:
            G.add_edge(addr, jump)
        if fail and fail in block_addrs and fail != jump:
            G.add_edge(addr, fail)

    return G


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <stripped_binary> <non_stripped_path> <output_dir>")
        sys.exit(1)

    stripped_path = sys.argv[1]
    unstrip_path = sys.argv[2]
    output_dir = sys.argv[3]

    assert os.path.exists(stripped_path), f"Stripped binary not found: {stripped_path}"
    assert os.path.exists(unstrip_path), f"Non-stripped binary not found: {unstrip_path}"
    os.makedirs(output_dir, exist_ok=True)

    # Read symbol table from non-stripped binary for IDA-compatible naming
    base = Binarybase(unstrip_path)

    # Open r2 on the non-stripped binary
    r2 = r2pipe.open(unstrip_path, flags=["-2"])
    for k, v in R2_CFG.items():
        r2.cmd(f"e {k}={v}")

    r2.cmd("aaaa")

    # Get all function addresses from r2
    r2_funcs = {f["addr"] for f in json.loads(r2.cmd("aflj"))}

    saved = {}
    for func_addr in r2_funcs:
        func_name = base.addr2name.get(func_addr, -1)
        if func_name == -1:
            func_name = f"sub_{func_addr:x}"

        G = extract_function(r2, func_addr)

        if G.number_of_nodes() == 0:
            continue

        saved[func_name] = [func_addr, [], b"", G, None]

    # Save pickle
    binary_name = os.path.basename(unstrip_path)
    out_path = os.path.join(output_dir, f"{binary_name}_extract.pkl")
    with open(out_path, "wb") as f:
        pickle.dump(dict(saved), f)

    print(f"[+] {len(saved)} functions saved to {out_path}")

    r2.quit()


if __name__ == "__main__":
    main()
