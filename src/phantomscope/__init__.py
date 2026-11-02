"""phantomscope - DMA-powered reverse engineering toolkit.

The package is split into three layers:

* ``phantomscope.backend`` - memory acquisition backends (MemProcFS / mock).
* ``phantomscope.analysis`` - static PE analysis (headers, imports, disassembly,
  functions, cross references, strings, pattern scanning).
* ``phantomscope.dynamic`` - live analysis on top of a backend (memory reads and
  writes, patch journal, scans, pointer chains, thread sampling, watchpoints).

``phantomscope.mcp_server`` exposes all of it through the Model Context
Protocol and ``phantomscope.cli`` provides a small command line front end.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
