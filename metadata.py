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
    InterfaceImpl = 0x09
    MemberRef = 0x0A
    DeclSecurity = 0x0E
    StandAloneSig = 0x11
    Event = 0x14
    Property = 0x17
    ModuleRef = 0x1A
    TypeSpec = 0x1B
    Assembly = 0x20
    AssemblyRef = 0x23
    File = 0x26
    ExportedType = 0x27
    ManifestResource = 0x28
    GenericParam = 0x2A
    MethodSpec = 0x2B
    GenericParamConstraint = 0x2C
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


# ---- coded-index definitions (referenced tables, tag-bit count) ------------
# 0xFF marks an unused tag slot (its row count is treated as 0 for sizing).
CODED = {
    "TypeDefOrRef":    ([0x02, 0x01, 0x1B], 2),
    "HasConstant":     ([0x04, 0x08, 0x17], 2),
    "HasCustomAttribute": ([0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00,
                            0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23,
                            0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B], 5),
    "HasFieldMarshal": ([0x04, 0x08], 1),
    "HasDeclSecurity": ([0x02, 0x06, 0x20], 2),
    "MemberRefParent": ([0x02, 0x01, 0x1A, 0x06, 0x1B], 3),
    "HasSemantics":    ([0x14, 0x17], 1),
    "MethodDefOrRef":  ([0x06, 0x0A], 1),
    "MemberForwarded": ([0x04, 0x06], 1),
    "Implementation":  ([0x26, 0x23, 0x27], 2),
    "CustomAttributeType": ([0xFF, 0xFF, 0x06, 0x0A, 0xFF], 3),
    "ResolutionScope": ([0x00, 0x1A, 0x23, 0x01], 2),
    "TypeOrMethodDef": ([0x02, 0x06], 1),
}

# Row schemas for every metadata table (ECMA-335 II.22). Column kinds:
#   'u16','u32'                       fixed ints
#   'string','guid','blob'            heap indexes (size from heapSizes byte)
#   ('idx', table_id)                 simple index into one table
#   ('coded', name)                   coded index (see CODED)
T = Table
SCHEMAS = {
    0x00: ["u16", "string", "guid", "guid", "guid"],                       # Module
    0x01: [("coded", "ResolutionScope"), "string", "string"],              # TypeRef
    0x02: ["u32", "string", "string", ("coded", "TypeDefOrRef"),
           ("idx", T.Field), ("idx", T.MethodDef)],                        # TypeDef
    0x03: [("idx", T.Field)],                                              # FieldPtr
    0x04: ["u16", "string", "blob"],                                       # Field
    0x05: [("idx", T.MethodDef)],                                          # MethodPtr
    0x06: ["u32", "u16", "u16", "string", "blob", ("idx", T.Param)],       # MethodDef
    0x07: [("idx", T.Param)],                                              # ParamPtr
    0x08: ["u16", "u16", "string"],                                        # Param
    0x09: [("idx", T.TypeDef), ("coded", "TypeDefOrRef")],                 # InterfaceImpl
    0x0A: [("coded", "MemberRefParent"), "string", "blob"],                # MemberRef
    0x0B: ["u16", ("coded", "HasConstant"), "blob"],                       # Constant
    0x0C: [("coded", "HasCustomAttribute"),
           ("coded", "CustomAttributeType"), "blob"],                      # CustomAttribute
    0x0D: [("coded", "HasFieldMarshal"), "blob"],                          # FieldMarshal
    0x0E: ["u16", ("coded", "HasDeclSecurity"), "blob"],                   # DeclSecurity
    0x0F: ["u16", "u32", ("idx", T.TypeDef)],                              # ClassLayout
    0x10: ["u32", ("idx", T.Field)],                                       # FieldLayout
    0x11: ["blob"],                                                        # StandAloneSig
    0x12: [("idx", T.TypeDef), ("idx", T.Event)],                          # EventMap
    0x13: [("idx", T.Event)],                                              # EventPtr
    0x14: ["u16", "string", ("coded", "TypeDefOrRef")],                    # Event
    0x15: [("idx", T.TypeDef), ("idx", T.Property)],                       # PropertyMap
    0x16: [("idx", T.Property)],                                           # PropertyPtr
    0x17: ["u16", "string", "blob"],                                       # Property
    0x18: ["u16", ("idx", T.MethodDef), ("coded", "HasSemantics")],        # MethodSemantics
    0x19: [("idx", T.TypeDef), ("coded", "MethodDefOrRef"),
           ("coded", "MethodDefOrRef")],                                   # MethodImpl
    0x1A: ["string"],                                                      # ModuleRef
    0x1B: ["blob"],                                                        # TypeSpec
    0x1C: ["u16", ("coded", "MemberForwarded"), "string",
           ("idx", T.ModuleRef)],                                          # ImplMap
    0x1D: ["u32", ("idx", T.Field)],                                       # FieldRVA
    0x1E: ["u32", "u32"],                                                  # ENCLog
    0x1F: ["u32"],                                                         # ENCMap
    0x20: ["u32", "u16", "u16", "u16", "u16", "u32",
           "blob", "string", "string"],                                    # Assembly
    0x21: ["u32"],                                                         # AssemblyProcessor
    0x22: ["u32", "u32", "u32"],                                           # AssemblyOS
    0x23: ["u16", "u16", "u16", "u16", "u32",
           "blob", "string", "string", "blob"],                           # AssemblyRef
    0x24: ["u32", ("idx", T.AssemblyRef)],                                 # AssemblyRefProcessor
    0x25: ["u32", "u32", "u32", ("idx", T.AssemblyRef)],                   # AssemblyRefOS
    0x26: ["u32", "string", "blob"],                                       # File
    0x27: ["u32", "u32", "string", "string", ("coded", "Implementation")], # ExportedType
    0x28: ["u32", "u32", "string", ("coded", "Implementation")],           # ManifestResource
    0x29: [("idx", T.TypeDef), ("idx", T.TypeDef)],                        # NestedClass
    0x2A: ["u16", "u16", ("coded", "TypeOrMethodDef"), "string"],          # GenericParam
    0x2B: [("coded", "MethodDefOrRef"), "blob"],                           # MethodSpec
    0x2C: [("idx", T.GenericParam), ("coded", "TypeDefOrRef")],            # GenericParamConstraint
}
LAST_TABLE = 0x2C


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
    _typedefs: dict = field(default_factory=dict)    # row -> "NS.Type"
    _typerefs: dict = field(default_factory=dict)    # row -> "NS.Type"
    _typespecs: dict = field(default_factory=dict)   # row -> "Type<...>"
    _memberrefs: dict = field(default_factory=dict)  # row -> "Type::name"
    _fields: dict = field(default_factory=dict)      # row -> "Type::name"
    _methodspecs: dict = field(default_factory=dict)  # row -> "method<...>"
    _field_rvas: dict = field(default_factory=dict)   # field row -> data RVA
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
        blob_off = streams.get("#Blob", (0, 0))[0]
        self._us_off = streams.get("#US", (0, 0))[0]

        def get_string(idx):
            if not idx or not strings_off:
                return ""
            s = strings_off + idx
            end = data.index(b"\x00", s)
            return data[s:end].decode("utf-8", "replace")

        def get_blob(idx):
            if not idx or not blob_off:
                return b""
            n, p2 = read_compressed_uint(data, blob_off + idx)
            return data[p2:p2 + n]

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

        # Parse every metadata table sequentially (table N's offset depends on
        # the exact size of all tables before it, so we must walk them in order).
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

        # TypeDef -> "NS.Type"  (needed for signature decoding below)
        for i, r in enumerate(rows_by_table.get(Table.TypeDef, []), start=1):
            ns, name = get_string(r[2]), get_string(r[1])
            self._typedefs[i] = f"{ns}.{name}" if ns else name

        # ---- type-signature decoder (ECMA-335 II.23.2.12) -----------------
        # Renders TypeSpec blobs and generic arguments, e.g. GENERICINST over
        # ReadOnlySpan`1<Byte> -> "System.ReadOnlySpan<byte>".
        PRIM = {
            0x01: "void", 0x02: "bool", 0x03: "char", 0x04: "sbyte",
            0x05: "byte", 0x06: "short", 0x07: "ushort", 0x08: "int",
            0x09: "uint", 0x0A: "long", 0x0B: "ulong", 0x0C: "float",
            0x0D: "double", 0x0E: "string", 0x16: "typedref",
            0x18: "IntPtr", 0x19: "UIntPtr", 0x1C: "object",
        }

        def type_name_tdr(coded):
            tag, r = coded & 3, coded >> 2
            if tag == 0:
                return self._typedefs.get(r, f"typedef_{r}")
            if tag == 1:
                return self._typerefs.get(r, f"typeref_{r}")
            if tag == 2:
                return self._typespecs.get(r, f"typespec_{r}")
            return f"tdr_{coded}"

        def decode_type(b, p, depth=0):
            if p >= len(b) or depth > 12:
                return "?", p
            et = b[p]
            p += 1
            if et in PRIM:
                return PRIM[et], p
            if et in (0x11, 0x12):                 # VALUETYPE / CLASS
                tok, p = read_compressed_uint(b, p)
                return type_name_tdr(tok), p
            if et == 0x1D:                         # SZARRAY
                inner, p = decode_type(b, p, depth + 1)
                return inner + "[]", p
            if et in (0x0F, 0x10):                 # PTR / BYREF
                inner, p = decode_type(b, p, depth + 1)
                return inner + ("*" if et == 0x0F else "&"), p
            if et == 0x13:                         # VAR (class generic param)
                n, p = read_compressed_uint(b, p)
                return f"!{n}", p
            if et == 0x1E:                         # MVAR (method generic param)
                n, p = read_compressed_uint(b, p)
                return f"!!{n}", p
            if et == 0x15:                         # GENERICINST
                p += 1                             # CLASS/VALUETYPE marker
                tok, p = read_compressed_uint(b, p)
                base = type_name_tdr(tok).split("`")[0]
                argc, p = read_compressed_uint(b, p)
                args = []
                for _ in range(argc):
                    a, p = decode_type(b, p, depth + 1)
                    args.append(a)
                return f"{base}<{', '.join(args)}>", p
            return f"et_{et:02x}", p

        # TypeSpec (0x1B) -> decoded type name
        for i, r in enumerate(rows_by_table.get(Table.TypeSpec, []), start=1):
            name, _ = decode_type(get_blob(r[0]), 0)
            self._typespecs[i] = name

        # MemberRef -> "Owner::name" (owner via MemberRefParent: TypeRef/
        # TypeDef/TypeSpec are the ones that name a type).
        mrp_tables, mrp_bits = CODED["MemberRefParent"]
        for i, r in enumerate(rows_by_table.get(Table.MemberRef, []), start=1):
            cls_val, name_idx = r[0], r[1]
            tag = cls_val & ((1 << mrp_bits) - 1)
            row = cls_val >> mrp_bits
            owner = ""
            if tag < len(mrp_tables):
                pt = mrp_tables[tag]
                if pt == Table.TypeRef:
                    owner = self._typerefs.get(row, "")
                elif pt == Table.TypeDef:
                    owner = self._typedefs.get(row, "")
                elif pt == Table.TypeSpec:
                    owner = self._typespecs.get(row, "")
            name = get_string(name_idx)
            self._memberrefs[i] = f"{owner}::{name}" if owner else name

        # TypeDef ranges -> map each method/field row to its declaring type.
        # TypeDef cols: [Flags, Name, Namespace, Extends, FieldList, MethodList]
        typedefs = rows_by_table.get(Table.TypeDef, [])
        methoddefs = rows_by_table.get(Table.MethodDef, [])
        fielddefs = rows_by_table.get(Table.Field, [])
        method_type = {}
        field_type = {}
        for ti, tr in enumerate(typedefs):
            ns, name = get_string(tr[2]), get_string(tr[1])
            tfull = f"{ns}.{name}" if ns else name
            m_start = tr[5]
            m_end = typedefs[ti + 1][5] if ti + 1 < len(typedefs) else len(methoddefs) + 1
            for mrow in range(m_start, m_end):
                method_type[mrow] = tfull
            f_start = tr[4]
            f_end = typedefs[ti + 1][4] if ti + 1 < len(typedefs) else len(fielddefs) + 1
            for frow in range(f_start, f_end):
                field_type[frow] = tfull

        # Field (0x04) -> "Type::name"  (Field cols: [Flags, Name, Signature])
        for i, r in enumerate(fielddefs, start=1):
            tfull = field_type.get(i)
            fname = get_string(r[1])
            self._fields[i] = f"{tfull}::{fname}" if tfull else fname

        # FieldRVA (0x1D): field row -> RVA of its initial data in the image.
        # Cols: [RVA, Field]. Used for embedded constant blobs (array/span
        # literals live in <PrivateImplementationDetails>).
        for r in rows_by_table.get(0x1D, []):
            self._field_rvas[r[1]] = r[0]

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

        # MethodSpec (0x2B) -> "method<T, ...>"  (generic method instantiation).
        # Cols: [Method (MethodDefOrRef coded), Instantiation (blob)].
        mdor_tables, mdor_bits = CODED["MethodDefOrRef"]
        for i, r in enumerate(rows_by_table.get(Table.MethodSpec, []), start=1):
            mval, inst = r[0], r[1]
            tag = mval & ((1 << mdor_bits) - 1)
            mrow = mval >> mdor_bits
            base = f"methodspec_{i}"
            if tag < len(mdor_tables):
                if mdor_tables[tag] == Table.MethodDef:
                    m = self._method_by_token.get(0x06000000 | mrow)
                    base = m.name if m else f"methoddef_{mrow}"
                elif mdor_tables[tag] == Table.MemberRef:
                    base = self._memberrefs.get(mrow, f"memberref_{mrow}")
            # Instantiation blob: GENERICINST(0x0A) then argcount then Types.
            b = get_blob(inst)
            args = []
            if b:
                bp = 1 if b[0] == 0x0A else 0
                argc, bp = read_compressed_uint(b, bp)
                for _ in range(argc):
                    a, bp = decode_type(b, bp)
                    args.append(a)
            self._methodspecs[i] = f"{base}<{', '.join(args)}>" if args else base

    # ---- lookups the architecture needs -----------------------------------
    def method_at_rva(self, rva):
        for m in self.methods:
            if m.rva == rva:
                return m
        return None

    def _rva2off(self, rva):
        for va, vsize, praw, sraw, _c in self.segments:
            if va <= rva < va + max(vsize, sraw):
                return praw + (rva - va)
        return None

    def field_data(self, field_row, length):
        """Raw initial bytes of a static field with a FieldRVA (or None)."""
        rva = self._field_rvas.get(field_row)
        if rva is None:
            return None
        off = self._rva2off(rva)
        if off is None:
            return None
        return self._data[off:off + length]

    def resolve_token_address(self, token):
        """
        Address to navigate to for a token, or None if it has no local target.
        Only MethodDef tokens with a body map to a function in this view; the
        function entry is rva + body-header size (image_base is 0 here).
        """
        if token_table(token) == Table.MethodDef:
            m = self._method_by_token.get(token)
            if m and m.rva:
                return self.image_base + m.rva + m.code_offset
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
        if tbl == Table.Field:
            return self._fields.get(row, f"field_{row}")
        if tbl == Table.TypeRef:
            return self._typerefs.get(row, f"typeref_{row}")
        if tbl == Table.TypeDef:
            return self._typedefs.get(row, f"typedef_{row}")
        if tbl == Table.TypeSpec:
            return self._typespecs.get(row, f"typespec_{row}")
        if tbl == Table.MethodSpec:
            return self._methodspecs.get(row, f"methodspec_{row}")
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
