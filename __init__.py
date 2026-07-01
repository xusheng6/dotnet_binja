"""
dotnet_binja — a standalone Binary Ninja plugin for .NET / CIL binaries.

This package registers two cooperating components:

  * CILArchitecture  (cil_arch.py)   — decodes + lifts CIL bytecode
  * DotNetView       (dotnet_view.py) — parses the CLI metadata, lays out
                                        method bodies as functions, and hands
                                        the metadata to the architecture.

Drop this directory into your Binary Ninja user plugins folder (or add its
parent to PYTHONPATH) and it will self-register on import.
"""

from .cil_arch import CILArchitecture
from .dotnet_view import DotNetView

# Register the architecture first: the view refers to it by name.
CILArchitecture.register()

# The view type registers itself so the core will probe it on file open.
DotNetView.register()
