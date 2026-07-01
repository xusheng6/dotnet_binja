# dotnet_binja

A **standalone** Binary Ninja plugin scaffold for analyzing .NET / CIL binaries.
Not part of the Binary Ninja tree — drop it in your user plugins folder.

## Why two components

.NET assemblies differ from native code on **two** axes, so the plugin needs a
part for each:

| Concern | Component | File |
|---|---|---|
| *Where is the code, what is it named?* (file format) | `DotNetView` (BinaryView) | `dotnet_view.py` |
| *What does this instruction mean?* (semantics) | `CILArchitecture` (Architecture) | `cil_arch.py` |

The default PE view can't help: a managed PE's native entry point is just a stub
into the CLR, and the real code lives in method bodies described by **metadata**,
addressed by **tokens** rather than addresses. So:

- `DotNetView` parses the CLI/COR20 header + metadata, maps the image, and
  creates one function per `MethodDef` body.
- `CILArchitecture` decodes the stack-machine bytecode and lifts it to LLIL.
- They're **coupled**: operands are metadata tokens, so the view hands its parsed
  `DotNetMetadata` to the arch (`CILArchitecture.attach_metadata`) for token
  resolution during disassembly/lifting.

## Files

- `__init__.py`   — registers the arch and the view on import.
- `metadata.py`   — ECMA-335 metadata parsing (**skeleton**; the real work).
- `cil_arch.py`   — CIL Architecture: decode table + LLIL lifting (partial).
- `dotnet_view.py`— `.NET` BinaryView: recognition, mapping, function layout.
- `plugin.json`   — plugin manifest.

## Install (macOS)

```
ln -s ~/dotnet_binja "~/Library/Application Support/Binary Ninja/plugins/dotnet_binja"
```

Then open a managed `.exe`/`.dll`; the "DotNet" view type should offer itself.

## Roadmap / TODO (in rough order)

1. **metadata.py** — the load-bearing piece. Parse COR20 → metadata root →
   `#~` tables + heaps; enumerate `MethodDef` with names, RVAs, code offsets.
2. **RVA mapping** — map per PE section (VirtualAddress ↔ PointerToRawData)
   instead of the flat whole-file mapping in `dotnet_view.py`.
3. **Entry point** — resolve the CLR header `EntryPointToken`.
4. **Opcode coverage** — finish `OPCODES`/`EXT_OPCODES` from ECMA-335 Part III.
5. **Token-aware lifting** — resolve `call`/`ldstr`/`ldfld` tokens to targets,
   types, and literals; pop/push per method signatures.
6. **Eval-stack model** — decide between LLIL push/pop (current) vs. synthetic
   slot registers for better typing.
7. **Exception clauses**, generics, and a **Platform**/type-libraries for the
   BCL.

## Known design tension

Binary Ninja assumes register/native code; CIL is a typed stack VM. This
scaffold takes the native-plugin route (real disassembly + LLIL). If you only
want a decompiler-style view, a transpile-to-C# approach (ILSpy/dnSpy style)
may be less friction.
