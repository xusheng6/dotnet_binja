"""
cil_arch.py — a CIL (MSIL) Architecture for Binary Ninja.

CIL is a typed *stack machine*. This module decodes the opcode stream, renders
readable disassembly (resolving metadata tokens via the view's parsed
metadata), and provides control-flow so Binary Ninja can build the function
graph. LLIL lifting is intentionally shallow: branches/ret are modeled so the
CFG is correct, most data ops are `unimplemented()` for now.
"""

import struct

from binaryninja import (
    Architecture, RegisterInfo, InstructionInfo, InstructionTextToken,
)
from binaryninja.enums import BranchType, InstructionTextTokenType as T


# Operand kinds -> encoded size in bytes ('switch' is variable, handled below).
OSIZE = {
    "none": 0, "var": 2, "varshort": 1, "i": 4, "ishort": 1, "i8": 8,
    "r": 8, "rshort": 4, "br": 4, "brshort": 1,
    "method": 4, "field": 4, "type": 4, "string": 4, "tok": 4, "sig": 4,
    "switch": -1,
}

# Single-byte opcodes: value -> (mnemonic, operand-kind)
OPCODES = {
    0x00: ("nop", "none"), 0x01: ("break", "none"),
    0x02: ("ldarg.0", "none"), 0x03: ("ldarg.1", "none"),
    0x04: ("ldarg.2", "none"), 0x05: ("ldarg.3", "none"),
    0x06: ("ldloc.0", "none"), 0x07: ("ldloc.1", "none"),
    0x08: ("ldloc.2", "none"), 0x09: ("ldloc.3", "none"),
    0x0A: ("stloc.0", "none"), 0x0B: ("stloc.1", "none"),
    0x0C: ("stloc.2", "none"), 0x0D: ("stloc.3", "none"),
    0x0E: ("ldarg.s", "varshort"), 0x0F: ("ldarga.s", "varshort"),
    0x10: ("starg.s", "varshort"), 0x11: ("ldloc.s", "varshort"),
    0x12: ("ldloca.s", "varshort"), 0x13: ("stloc.s", "varshort"),
    0x14: ("ldnull", "none"), 0x15: ("ldc.i4.m1", "none"),
    0x16: ("ldc.i4.0", "none"), 0x17: ("ldc.i4.1", "none"),
    0x18: ("ldc.i4.2", "none"), 0x19: ("ldc.i4.3", "none"),
    0x1A: ("ldc.i4.4", "none"), 0x1B: ("ldc.i4.5", "none"),
    0x1C: ("ldc.i4.6", "none"), 0x1D: ("ldc.i4.7", "none"),
    0x1E: ("ldc.i4.8", "none"), 0x1F: ("ldc.i4.s", "ishort"),
    0x20: ("ldc.i4", "i"), 0x21: ("ldc.i8", "i8"),
    0x22: ("ldc.r4", "rshort"), 0x23: ("ldc.r8", "r"),
    0x25: ("dup", "none"), 0x26: ("pop", "none"),
    0x27: ("jmp", "method"), 0x28: ("call", "method"),
    0x29: ("calli", "sig"), 0x2A: ("ret", "none"),
    0x2B: ("br.s", "brshort"), 0x2C: ("brfalse.s", "brshort"),
    0x2D: ("brtrue.s", "brshort"), 0x2E: ("beq.s", "brshort"),
    0x2F: ("bge.s", "brshort"), 0x30: ("bgt.s", "brshort"),
    0x31: ("ble.s", "brshort"), 0x32: ("blt.s", "brshort"),
    0x33: ("bne.un.s", "brshort"), 0x34: ("bge.un.s", "brshort"),
    0x35: ("bgt.un.s", "brshort"), 0x36: ("ble.un.s", "brshort"),
    0x37: ("blt.un.s", "brshort"), 0x38: ("br", "br"),
    0x39: ("brfalse", "br"), 0x3A: ("brtrue", "br"),
    0x3B: ("beq", "br"), 0x3C: ("bge", "br"), 0x3D: ("bgt", "br"),
    0x3E: ("ble", "br"), 0x3F: ("blt", "br"), 0x40: ("bne.un", "br"),
    0x41: ("bge.un", "br"), 0x42: ("bgt.un", "br"), 0x43: ("ble.un", "br"),
    0x44: ("blt.un", "br"), 0x45: ("switch", "switch"),
    0x46: ("ldind.i1", "none"), 0x47: ("ldind.u1", "none"),
    0x48: ("ldind.i2", "none"), 0x49: ("ldind.u2", "none"),
    0x4A: ("ldind.i4", "none"), 0x4B: ("ldind.u4", "none"),
    0x4C: ("ldind.i8", "none"), 0x4D: ("ldind.i", "none"),
    0x4E: ("ldind.r4", "none"), 0x4F: ("ldind.r8", "none"),
    0x50: ("ldind.ref", "none"), 0x51: ("stind.ref", "none"),
    0x52: ("stind.i1", "none"), 0x53: ("stind.i2", "none"),
    0x54: ("stind.i4", "none"), 0x55: ("stind.i8", "none"),
    0x56: ("stind.r4", "none"), 0x57: ("stind.r8", "none"),
    0x58: ("add", "none"), 0x59: ("sub", "none"), 0x5A: ("mul", "none"),
    0x5B: ("div", "none"), 0x5C: ("div.un", "none"), 0x5D: ("rem", "none"),
    0x5E: ("rem.un", "none"), 0x5F: ("and", "none"), 0x60: ("or", "none"),
    0x61: ("xor", "none"), 0x62: ("shl", "none"), 0x63: ("shr", "none"),
    0x64: ("shr.un", "none"), 0x65: ("neg", "none"), 0x66: ("not", "none"),
    0x67: ("conv.i1", "none"), 0x68: ("conv.i2", "none"),
    0x69: ("conv.i4", "none"), 0x6A: ("conv.i8", "none"),
    0x6B: ("conv.r4", "none"), 0x6C: ("conv.r8", "none"),
    0x6D: ("conv.u4", "none"), 0x6E: ("conv.u8", "none"),
    0x6F: ("callvirt", "method"), 0x70: ("cpobj", "type"),
    0x71: ("ldobj", "type"), 0x72: ("ldstr", "string"),
    0x73: ("newobj", "method"), 0x74: ("castclass", "type"),
    0x75: ("isinst", "type"), 0x76: ("conv.r.un", "none"),
    0x79: ("unbox", "type"), 0x7A: ("throw", "none"),
    0x7B: ("ldfld", "field"), 0x7C: ("ldflda", "field"),
    0x7D: ("stfld", "field"), 0x7E: ("ldsfld", "field"),
    0x7F: ("ldsflda", "field"), 0x80: ("stsfld", "field"),
    0x81: ("stobj", "type"), 0x82: ("conv.ovf.i1.un", "none"),
    0x8C: ("box", "type"), 0x8D: ("newarr", "type"),
    0x8E: ("ldlen", "none"), 0x8F: ("ldelema", "type"),
    0x90: ("ldelem.i1", "none"), 0x91: ("ldelem.u1", "none"),
    0x92: ("ldelem.i2", "none"), 0x93: ("ldelem.u2", "none"),
    0x94: ("ldelem.i4", "none"), 0x95: ("ldelem.u4", "none"),
    0x96: ("ldelem.i8", "none"), 0x97: ("ldelem.i", "none"),
    0x98: ("ldelem.r4", "none"), 0x99: ("ldelem.r8", "none"),
    0x9A: ("ldelem.ref", "none"), 0x9B: ("stelem.i", "none"),
    0x9C: ("stelem.i1", "none"), 0x9D: ("stelem.i2", "none"),
    0x9E: ("stelem.i4", "none"), 0x9F: ("stelem.i8", "none"),
    0xA0: ("stelem.r4", "none"), 0xA1: ("stelem.r8", "none"),
    0xA2: ("stelem.ref", "none"), 0xA3: ("ldelem", "type"),
    0xA4: ("stelem", "type"), 0xA5: ("unbox.any", "type"),
    0xDC: ("endfinally", "none"), 0xDD: ("leave", "br"),
    0xDE: ("leave.s", "brshort"), 0xDF: ("stind.i", "none"),
    0xE0: ("conv.u", "none"),
}

# 0xFE-prefixed two-byte opcodes: second byte -> (mnemonic, operand-kind)
EXT_OPCODES = {
    0x00: ("arglist", "none"), 0x01: ("ceq", "none"), 0x02: ("cgt", "none"),
    0x03: ("cgt.un", "none"), 0x04: ("clt", "none"), 0x05: ("clt.un", "none"),
    0x06: ("ldftn", "method"), 0x07: ("ldvirtftn", "method"),
    0x09: ("ldarg", "var"), 0x0A: ("ldarga", "var"), 0x0B: ("starg", "var"),
    0x0C: ("ldloc", "var"), 0x0D: ("ldloca", "var"), 0x0E: ("stloc", "var"),
    0x0F: ("localloc", "none"), 0x11: ("endfilter", "none"),
    0x12: ("unaligned.", "ishort"), 0x13: ("volatile.", "none"),
    0x14: ("tail.", "none"), 0x15: ("initobj", "type"),
    0x16: ("constrained.", "type"), 0x17: ("cpblk", "none"),
    0x18: ("initblk", "none"), 0x1A: ("rethrow", "none"),
    0x1C: ("sizeof", "type"), 0x1D: ("refanytype", "none"),
    0x1E: ("readonly.", "none"),
}

# Max branch targets InstructionInfo can hold (BN_MAX_INSTRUCTION_BRANCHES).
MAX_BRANCHES = 3

# instructions that resolve a metadata/user-string token for display
TOKEN_KINDS = {"method", "field", "type", "string", "tok", "sig"}
# branch mnemonics that take a target and fall through if not taken
COND_BRANCH = {
    "brfalse.s", "brtrue.s", "beq.s", "bge.s", "bgt.s", "ble.s", "blt.s",
    "bne.un.s", "bge.un.s", "bgt.un.s", "ble.un.s", "blt.un.s",
    "brfalse", "brtrue", "beq", "bge", "bgt", "ble", "blt",
    "bne.un", "bge.un", "bgt.un", "ble.un", "blt.un",
}


class CILArchitecture(Architecture):
    name = "cil"
    address_size = 4
    default_int_size = 4
    instr_alignment = 1
    # switch is 5 + 4*count bytes; this covers switches up to ~62 cases. Larger
    # ones are still decoded for length, but only the targets within the buffer
    # Binary Ninja provides get rendered (see the clamping in the switch paths).
    max_instr_length = 256

    regs = {"sp": RegisterInfo("sp", 4)}
    stack_pointer = "sp"

    _metadata_by_base = {}

    @classmethod
    def attach_metadata(cls, image_base, metadata):
        cls._metadata_by_base[image_base] = metadata

    def _md(self):
        for md in self._metadata_by_base.values():
            return md
        return None

    # ---- decode ------------------------------------------------------------
    def _decode(self, data):
        """Return (mnemonic, kind, operand_bytes, length) or None."""
        if not data:
            return None
        op = data[0]
        if op == 0xFE:
            if len(data) < 2:
                return None
            ent = EXT_OPCODES.get(data[1])
            if ent is None:
                return ("unk.fe", "none", b"", 2)
            name, kind = ent
            n = OSIZE[kind]
            return (name, kind, data[2:2 + n], 2 + n)
        ent = OPCODES.get(op)
        if ent is None:
            return (".byte", "none", b"", 1)   # keep sweeping past unknowns
        name, kind = ent
        if kind == "switch":
            if len(data) < 5:
                return None
            count = struct.unpack_from("<I", data, 1)[0]
            length = 5 + 4 * count
            return (name, kind, data[1:length], length)
        n = OSIZE[kind]
        return (name, kind, data[1:1 + n], 1 + n)

    def _branch_target(self, kind, operand, addr, length):
        if kind == "brshort":
            return addr + length + struct.unpack("<b", operand)[0]
        if kind == "br":
            return addr + length + struct.unpack("<i", operand)[0]
        return None

    # ---- required hooks ----------------------------------------------------
    def get_instruction_info(self, data, addr):
        dec = self._decode(data)
        if dec is None:
            return None
        name, kind, operand, length = dec
        info = InstructionInfo()
        info.length = length

        if name in ("ret", "endfinally", "rethrow"):
            info.add_branch(BranchType.FunctionReturn)
        elif name == "throw":
            info.add_branch(BranchType.FunctionReturn)
        elif name in ("br", "br.s", "leave", "leave.s"):
            tgt = self._branch_target(kind, operand, addr, length)
            if tgt is not None:
                info.add_branch(BranchType.UnconditionalBranch, tgt)
        elif name in COND_BRANCH:
            tgt = self._branch_target(kind, operand, addr, length)
            if tgt is not None:
                info.add_branch(BranchType.TrueBranch, tgt)
                info.add_branch(BranchType.FalseBranch, addr + length)
        elif name == "switch" and len(operand) >= 4:
            count = struct.unpack_from("<I", operand, 0)[0]
            avail = (len(operand) - 4) // 4        # entries actually in buffer
            n = min(count, avail)
            # InstructionInfo holds at most BN_MAX_INSTRUCTION_BRANCHES (3)
            # branches. Enumerate case targets only when they all fit; a larger
            # jump table becomes a single unresolved indirect branch so the
            # block still terminates instead of overflowing the array.
            if 0 < n <= MAX_BRANCHES:
                base = addr + length
                for i in range(n):
                    rel = struct.unpack_from("<i", operand, 4 + 4 * i)[0]
                    info.add_branch(BranchType.IndirectBranch, base + rel)
            elif n > MAX_BRANCHES:
                info.add_branch(BranchType.IndirectBranch)   # unresolved
        return info

    def get_instruction_text(self, data, addr):
        dec = self._decode(data)
        if dec is None:
            return None
        name, kind, operand, length = dec
        toks = [InstructionTextToken(T.InstructionToken, name)]

        def space():
            toks.append(InstructionTextToken(T.TextToken, " "))

        if kind in TOKEN_KINDS and len(operand) == 4:
            token = struct.unpack("<I", operand)[0]
            md = self._md()
            label = md.resolve_token(token) if md else f"token_{token:08x}"
            target = md.resolve_token_address(token) if md else None
            space()
            if target is not None:
                # Local method: a function symbol exists at `target`, so emit a
                # CodeSymbolToken directly. This is the navigable token type the
                # GUI honors on double-click (PossibleAddressToken/
                # CodeRelativeAddressToken render a hover preview but the GUI's
                # interactive token stays non-navigable).
                toks.append(InstructionTextToken(T.CodeSymbolToken,
                                                 label, target))
            else:
                # External member / string / type: no local address, so keep it
                # as plain text (double-click must not jump to a bogus token).
                toks.append(InstructionTextToken(T.TextToken, label))
        elif kind in ("i", "ishort", "var", "varshort"):
            fmt = "<i" if kind == "i" else ("<b" if kind in ("ishort", "varshort") else "<h")
            if kind == "var":
                fmt = "<H"
            val = struct.unpack(fmt, operand)[0]
            space()
            toks.append(InstructionTextToken(T.IntegerToken, str(val), val))
        elif kind == "i8" and len(operand) == 8:
            val = struct.unpack("<q", operand)[0]
            space()
            toks.append(InstructionTextToken(T.IntegerToken, str(val), val))
        elif kind in ("brshort", "br"):
            tgt = self._branch_target(kind, operand, addr, length)
            space()
            toks.append(InstructionTextToken(T.PossibleAddressToken, f"0x{tgt:x}", tgt))
        elif kind == "switch" and len(operand) >= 4:
            count = struct.unpack_from("<I", operand, 0)[0]
            space()
            toks.append(InstructionTextToken(T.IntegerToken, f"[{count}]", count))
        return toks, length

    def get_instruction_low_level_il(self, data, addr, il):
        # Disassembly-only plugin: we do NOT model the CIL evaluation stack.
        # BUT Binary Ninja confirms control-flow *terminators* via the lifted
        # IL — if `ret`/`throw`/`br` don't emit a real terminator op, analysis
        # distrusts the FunctionReturn/branch from get_instruction_info and
        # spills the block into the following bytes. So we lift terminators
        # only; every data op stays unimplemented.
        # dec = self._decode(data)
        # if dec is None:
        #     return None
        # name, kind, operand, length = dec

        # if name in ("ret", "endfinally"):
        #     il.append(il.ret(il.const(4, 0)))
        # elif name in ("throw", "rethrow"):
        #     il.append(il.no_ret())
        # elif name in ("br", "br.s", "leave", "leave.s"):
        #     tgt = self._branch_target(kind, operand, addr, length)
        #     if tgt is not None:
        #         il.append(il.jump(il.const_pointer(4, tgt)))
        #     else:
        #         il.append(il.unimplemented())
        # else:
        #     il.append(il.unimplemented())
        # return length
        return None