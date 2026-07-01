"""
dotnet_view.py — a BinaryView for .NET assemblies.

Responsibilities (the file-format half of the problem):
  * Recognize a managed PE (COR20 header present in data directory 14).
  * Map the image so method-body RVAs are addressable.
  * Parse metadata (metadata.py) and, for every MethodDef, create a function at
    its code offset, name it, and set its architecture/platform to CIL.
  * Hand the parsed metadata to CILArchitecture so token resolution works.

We build *on top of* the raw file rather than re-deriving the PE view: the
existing PE parser already validates the DOS/NT headers; here we only need the
CLI-specific structures. A production plugin may prefer to parse the section
table itself so RVA<->file-offset mapping is exact.
"""

import struct

from binaryninja import BinaryView, Architecture, Platform
from binaryninja.enums import SegmentFlag, SectionSemantics, SymbolType
from binaryninja.types import Symbol

from .metadata import DotNetMetadata
from .cil_arch import CILArchitecture


# PE data directory index 14 = CLR Runtime Header (COR20).
COR20_DIRECTORY_INDEX = 14


class DotNetView(BinaryView):
    name = "DotNet"
    long_name = ".NET (CIL) Assembly"

    def __init__(self, data):
        # Use the raw file as the parent BinaryView.
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        # NB: `raw`, `metadata`, etc. are existing BinaryView properties — use
        # underscore-prefixed names to avoid clobbering them.
        self._raw = data
        self._dotnet_md = None

    # ---- recognition -------------------------------------------------------
    @classmethod
    def is_valid_for_data(cls, data):
        """Cheap check: valid PE whose COR20 data directory is non-empty."""
        if data.read(0, 2) != b"MZ":
            return False
        e_lfanew = _u32(data, 0x3C)
        if e_lfanew is None or data.read(e_lfanew, 4) != b"PE\x00\x00":
            return False
        # Optional header magic: PE32 (0x10B) vs PE32+ (0x20B) changes offsets.
        opt = e_lfanew + 24
        magic = _u16(data, opt)
        if magic == 0x10B:
            dir_base = opt + 96           # PE32 data directories
        elif magic == 0x20B:
            dir_base = opt + 112          # PE32+ data directories
        else:
            return False
        cor20_rva = _u32(data, dir_base + COR20_DIRECTORY_INDEX * 8)
        cor20_size = _u32(data, dir_base + COR20_DIRECTORY_INDEX * 8 + 4)
        return bool(cor20_rva) and bool(cor20_size)

    # ---- load --------------------------------------------------------------
    def init(self):
        try:
            self.arch = Architecture["cil"]
            self.platform = self.arch.standalone_platform

            # Addresses live in RVA space (image_base 0), so `addr == RVA`.
            # This keeps everything in the 32-bit space the CIL arch expects
            # regardless of the PE's real (possibly 64-bit) ImageBase.
            image_base = 0x0

            length = self._raw.length
            raw_bytes = self._raw.read(0, length)
            self._dotnet_md = DotNetMetadata.parse(raw_bytes, image_base)
            CILArchitecture.attach_metadata(image_base, self._dotnet_md)

            # Map each PE section at its VirtualAddress so RVAs resolve to the
            # right file bytes (method bodies are addressed by RVA).
            EXEC = 0x20000000  # IMAGE_SCN_MEM_EXECUTE
            for va, vsize, praw, sraw, chars in self._dotnet_md.segments:
                if not sraw:
                    continue
                flags = SegmentFlag.SegmentReadable
                sem = SectionSemantics.ReadOnlyDataSectionSemantics
                if chars & EXEC:
                    flags |= SegmentFlag.SegmentExecutable
                    sem = SectionSemantics.ReadOnlyCodeSectionSemantics
                vlen = max(vsize, sraw)
                self.add_auto_segment(image_base + va, vlen, praw, sraw, flags)
                self.add_auto_section(f"sec_{va:x}", image_base + va, vlen, sem)

            # Create a function per method body.
            for method in self._dotnet_md.methods:
                if not method.rva:
                    continue          # abstract / pinvoke / interface: no body
                entry = image_base + method.rva + method.code_offset
                self.add_function(entry, plat=self.platform)
                self.define_auto_symbol(
                    Symbol(SymbolType.FunctionSymbol, entry, method.name)
                )

            ep = self._dotnet_md.entry_point
            if ep:
                self.add_entry_point(image_base + ep)
            return True
        except Exception:
            import traceback
            traceback.print_exc()
            return False

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self._dotnet_md.entry_point if self._dotnet_md else 0

    def perform_get_address_size(self):
        return 4


# ---- little-endian readers over a raw BinaryView ---------------------------
def _u16(data, off):
    b = data.read(off, 2)
    return struct.unpack("<H", b)[0] if b and len(b) == 2 else None


def _u32(data, off):
    b = data.read(off, 4)
    return struct.unpack("<I", b)[0] if b and len(b) == 4 else None
