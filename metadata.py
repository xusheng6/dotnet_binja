"""
metadata.py — .NET (ECMA-335) metadata parsing.

Walks: PE header -> data directory[14] (COR20/CLR header) -> metadata root
("BSJB") -> "#~" table stream + "#Strings"/"#US" heaps -> MethodDef/TypeDef/
TypeRef/MemberRef rows.

Enough is parsed to (a) lay out every method body as a function and (b) resolve
the tokens used by call/ldstr/ldfld so disassembly is readable. Signatures are
skipped. Only metadata tables 0x00..0x0A are decoded (that's all we need to
reach MethodRef); tables after that are ignored.
"""

import struct
from dataclasses import dataclass, field
from typing import Optional


# ---- metadata token helpers ------------------------------------------------
class Table:
    Module = 0x00
    TypeRef = 0x01
    TypeDef = 0x02
    Field = 0x04
    MethodDef = 0x06
    Param = 0x08
    MemberRef = 0x0A
    ModuleRef = 0x1A
    TypeSpec = 0x1B
    AssemblyRef = 0x23
    UserString = 0x70    # ldstr operands index the "#US" heap with this prefix


def token_table(token):
    return (token >> 24) & 0xFF


def token_row(token):
    return token & 0x00FFFFFF


# ---- little-endian scalar reads -------------------------------------------
def u8(d, o):
    return d[o]


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def u64(d, o):
    return struct.unpack_from("<Q", d, o)[0]


def read_compressed_uint(d, o):
    """ECMA-335 II.23.2 compressed unsigned int. Returns (value, next_off)."""
    b = d[o]
    if b & 0x80 == 0:
        return b, o + 1
    if b & 0xC0 == 0x80:
        return ((b & 0x3F) << 8) | d[o + 1], o + 2
    return (((b & 0x1F) << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]), o + 4


# ---- coded-index definitions (tables referenced, tag-bit count) ------------
CODED = {
    "TypeDefOrRef":    ([Table.TypeDef, Table.TypeRef, Table.TypeSpec], 2),
    "ResolutionScope": ([Table.Module, Table.ModuleRef, Table.AssemblyRef, Table.TypeRef], 2),
    "MemberRefParent": ([Table.TypeDef, Table.TypeRef, Table.ModuleRef,
                         Table.MethodDef, Table.TypeSpec], 3),
}

# Row schemas for tables 0x00..0x0A. Column kinds:
#   'u16','u32'                       fixed ints
#   'string','guid','blob'            heap indexes (size from heapSizes byte)
#   ('idx', table_id)                 simple index into one table
#   ('coded', name)                   coded index (see CODED)
SCHEMAS = {
    0x00: ["u16", "string", "guid", "guid", "guid"],                       # Module
    0x01: [("coded", "ResolutionScope"), "string", "string"],             # TypeRef
    0x02: ["u32", "string", "string", ("coded", "TypeDefOrRef"),
           ("idx", Table.Field), ("idx", Table.MethodDef)],               # TypeDef
    0x03: [("idx", Table.Field)],                                          # FieldPtr
    0x04: ["u16", "string", "blob"],                                       # Field
    0x05: [("idx", Table.MethodDef)],                                      # MethodPtr
    0x06: ["u32", "u16", "u16", "string", "blob", ("idx", Table.Param)],   # MethodDef
    0x07: [("idx", Table.Param)],                                          # ParamPtr
    0x08: ["u16", "u16", "string"],                                        # Param
    0x09: [("idx", Table.TypeDef), ("coded", "TypeDefOrRef")],            # InterfaceImpl
    0x0A: [("coded", "MemberRefParent"), "string", "blob"],               # MemberRef
}
LAST_TABLE = 0x0A


@dataclass
class Method:
    token: int
    rva: int                 # RVA of the method body (header + code)
    name: str
    code_offset: int = 0     # body-header size (1 tiny / 12 fat)
    code_size: int = 0


class _PE:
    """Just enough PE to find the CLR header, sections, and RVA->offset map."""

    def __init__(self, data):
        self.data = data
        e_lfanew = u32(data, 0x3C)
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("not a PE")
        coff = e_lfanew + 4
        num_sections = u16(data, coff + 2)
        size_opt = u16(data, coff + 16)
        opt = coff + 20
        magic = u16(data, opt)
        if magic == 0x10B:            # PE32
            self.image_base = u32(data, opt + 28)
            dir_base = opt + 96
        elif magic == 0x20B:          # PE32+
            self.image_base = u64(data, opt + 24)
            dir_base = opt + 112
        else:
            raise ValueError("bad optional header magic")
        self.cor20_rva = u32(data, dir_base + 14 * 8)
        self.cor20_size = u32(data, dir_base + 14 * 8 + 4)

        self.sections = []            # (name, va, vsize, praw, sraw, chars)
        sec = opt + size_opt
        for i in range(num_sections):
            b = sec + i * 40
            name = data[b:b + 8].rstrip(b"\x00").decode("ascii", "replace")
            vsize = u32(data, b + 8)
            va = u32(data, b + 12)
            sraw = u32(data, b + 16)
            praw = u32(data, b + 20)
            chars = u32(data, b + 36)
            self.sections.append((name, va, vsize, praw, sraw, chars))

    def rva2off(self, rva):
        for _n, va, vsize, praw, sraw, _c in self.sections:
            if va <= rva < va + max(vsize, sraw):
                return praw + (rva - va)
        return None


@dataclass
class DotNetMetadata:
    image_base: int = 0
    entry_point: int = 0
    methods: list = field(default_factory=list)
    segments: list = field(default_factory=list)   # (va, vsize, praw, sraw, chars)
    _method_by_token: dict = field(default_factory=dict)
    _typerefs: dict = field(default_factory=dict)   # row -> "NS.Type"
    _memberrefs: dict = field(default_factory=dict)  # row -> "NS.Type::name"
    _us_off: int = 0
    _data: bytes = b""

    # ---- entry point -------------------------------------------------------
    @classmethod
    def parse(cls, data, image_base=0):
        md = cls(image_base=image_base, _data=data)
        try:
            md._parse(data)
        except Exception:
            import traceback
            traceback.print_exc()
        return md

    def _parse(self, data):
        pe = _PE(data)
        # Map addresses in RVA space (view uses image_base 0).
        self.segments = [(va, vsize, praw, sraw, chars)
                         for _n, va, vsize, praw, sraw, chars in pe.sections]

        if not pe.cor20_rva:
            return
        cor = pe.rva2off(pe.cor20_rva)
        md_rva = u32(data, cor + 8)
        entry_token = u32(data, cor + 20)
        root = pe.rva2off(md_rva)
        if data[root:root + 4] != b"BSJB":
            return

        # metadata root -> stream headers
        ver_len = u32(data, root + 12)
        p = root + 16 + ((ver_len + 3) & ~3)
        num_streams = u16(data, p + 2)
        p += 4
        streams = {}
        for _ in range(num_streams):
            off = u32(data, p)
            size = u32(data, p + 4)
            name_start = p + 8
            end = data.index(b"\x00", name_start)
            name = data[name_start:end].decode("ascii", "replace")
            padded = ((end - name_start) + 1 + 3) & ~3
            streams[name] = (root + off, size)
            p = name_start + padded

        strings_off = streams.get("#Strings", (0, 0))[0]
        self._us_off = streams.get("#US", (0, 0))[0]

        def get_string(idx):
            if not idx or not strings_off:
                return ""
            s = strings_off + idx
            end = data.index(b"\x00", s)
            return data[s:end].decode("utf-8", "replace")

        # table stream ("#~" compressed, "#-" uncompressed)
        tstream = streams.get("#~") or streams.get("#-")
        if not tstream:
            return
        ts = tstream[0]
        heap_sizes = data[ts + 6]
        valid = u64(data, ts + 8)
        p = ts + 24
        rowcounts = {}
        for tid in range(64):
            if (valid >> tid) & 1:
                rowcounts[tid] = u32(data, p)
                p += 4
        tables_start = p

        str_sz = 4 if heap_sizes & 1 else 2
        guid_sz = 4 if heap_sizes & 2 else 2
        blob_sz = 4 if heap_sizes & 4 else 2

        def idx_size(table_id):
            return 4 if rowcounts.get(table_id, 0) >= (1 << 16) else 2

        def coded_size(name):
            tables, tag_bits = CODED[name]
            maxrows = max((rowcounts.get(t, 0) for t in tables), default=0)
            return 4 if maxrows >= (1 << (16 - tag_bits)) else 2

        def col_width(kind):
            if kind == "u16":
                return 2
            if kind == "u32":
                return 4
            if kind == "string":
                return str_sz
            if kind == "guid":
                return guid_sz
            if kind == "blob":
                return blob_sz
            if kind[0] == "idx":
                return idx_size(kind[1])
            if kind[0] == "coded":
                return coded_size(kind[1])
            raise ValueError(kind)

        # Parse tables 0x00..0x0A sequentially.
        rows_by_table = {}
        p = tables_start
        for tid in range(0, LAST_TABLE + 1):
            if not (valid >> tid) & 1:
                rows_by_table[tid] = []
                continue
            schema = SCHEMAS[tid]
            widths = [col_width(k) for k in schema]
            n = rowcounts[tid]
            rows = []
            for _ in range(n):
                row = []
                for w in widths:
                    row.append(int.from_bytes(data[p:p + w], "little"))
                    p += w
                rows.append(row)
            rows_by_table[tid] = rows

        # TypeRef -> "NS.Type"
        for i, r in enumerate(rows_by_table.get(Table.TypeRef, []), start=1):
            ns, name = get_string(r[2]), get_string(r[1])
            self._typerefs[i] = f"{ns}.{name}" if ns else name

        # MemberRef -> "Owner::name" (owner resolved via MemberRefParent)
        _, mrp_bits = CODED["MemberRefParent"]
        mrp_tables = CODED["MemberRefParent"][0]
        for i, r in enumerate(rows_by_table.get(Table.MemberRef, []), start=1):
            cls_val, name_idx = r[0], r[1]
            tag = cls_val & ((1 << mrp_bits) - 1)
            row = cls_val >> mrp_bits
            owner = ""
            if tag < len(mrp_tables) and mrp_tables[tag] == Table.TypeRef:
                owner = self._typerefs.get(row, "")
            name = get_string(name_idx)
            self._memberrefs[i] = f"{owner}::{name}" if owner else name

        # TypeDef method ranges -> map each method row to its declaring type.
        typedefs = rows_by_table.get(Table.TypeDef, [])
        methoddefs = rows_by_table.get(Table.MethodDef, [])
        method_type = {}
        for ti, tr in enumerate(typedefs):
            start = tr[5]
            end = typedefs[ti + 1][5] if ti + 1 < len(typedefs) else len(methoddefs) + 1
            ns, name = get_string(tr[2]), get_string(tr[1])
            tfull = f"{ns}.{name}" if ns else name
            for mrow in range(start, end):
                method_type[mrow] = tfull

        # MethodDef -> Method (+ body header parse)
        for i, r in enumerate(methoddefs, start=1):
            rva = r[0]
            mname = get_string(r[3])
            tfull = method_type.get(i)
            full = f"{tfull}::{mname}" if tfull else mname
            token = 0x06000000 | i
            m = Method(token=token, rva=rva, name=full)
            if rva:
                off = pe.rva2off(rva)
                if off is not None:
                    hdr = data[off]
                    if hdr & 0x03 == 0x02:        # tiny format
                        m.code_offset, m.code_size = 1, hdr >> 2
                    elif hdr & 0x03 == 0x03:      # fat format
                        m.code_offset, m.code_size = 12, u32(data, off + 4)
            self.methods.append(m)
            self._method_by_token[token] = m

        if token_table(entry_token) == Table.MethodDef:
            em = self._method_by_token.get(entry_token)
            if em and em.rva:
                self.entry_point = em.rva + em.code_offset

    # ---- lookups the architecture needs -----------------------------------
    def method_at_rva(self, rva):
        for m in self.methods:
            if m.rva == rva:
                return m
        return None

    def resolve_token(self, token):
        tbl, row = token_table(token), token_row(token)
        if tbl == Table.UserString:
            return self._resolve_user_string(token)
        if tbl == Table.MethodDef:
            m = self._method_by_token.get(token)
            if m:
                return m.name
        if tbl == Table.MemberRef:
            return self._memberrefs.get(row, f"memberref_{row}")
        if tbl == Table.TypeRef:
            return self._typerefs.get(row, f"typeref_{row}")
        if tbl == Table.TypeDef:
            return f"typedef_{row}"
        return f"token_{token:08x}"

    def _resolve_user_string(self, token):
        off = token_row(token)
        if not self._us_off:
            return f'us_{off:x}'
        p = self._us_off + off
        try:
            n, p2 = read_compressed_uint(self._data, p)
            if n == 0:
                return '""'
            raw = self._data[p2:p2 + n - 1]        # trailing flag byte excluded
            return '"' + raw.decode("utf-16-le", "replace") + '"'
        except Exception:
            return f'us_{off:x}'
