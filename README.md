# phantomscope

**DMA-driven reverse engineering.** Static PE analysis, live memory inspection
over MemProcFS, snapshot emulation, and an MCP server that exposes all of it to
an LLM agent.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](#license)
[![Tests](https://img.shields.io/badge/tests-137%20passing-brightgreen.svg)](#tests)
[![MCP tools](https://img.shields.io/badge/MCP%20tools-74-informational.svg)](#tool-reference)
[![Windows](https://img.shields.io/badge/DMA%20backend-Windows-lightgrey.svg)](#install)

---

## What this is

DMA hardware (a PCILeech FPGA, or a memory dump) gives you read/write access to
physical memory — and nothing else. No thread suspension, no register context,
no single step, no breakpoints. phantomscope is built around that constraint: it
splits "understand and change a target" into four engines, each honest about
what it can actually do, and exposes the whole thing as **74 MCP tools** so an
agent can drive it.

It also runs with **no hardware at all** — the `mock` backend is a deterministic
synthetic target and the `physical` backend reads raw dumps, so the full pipeline
is testable in CI.

## What this is not

* **Not a debugger.** You cannot break on a live DMA target. The emulator is the
  substitute: capture the function and its data, then run it deterministically.
* **Not an injection tool.** It does not inject DLLs, load a driver, or execute
  new code in the target. `write` changes bytes that are already there, and
  every write is journaled and reversible.
* **Not a kernel-structure parser.** The `physical` backend deliberately assumes
  no OS: it finds PEs by header structure, not by walking `PsActiveProcessHead`.

> **Authorized use only.** Reading another machine's memory over DMA is illegal
> in most jurisdictions without written permission. Use phantomscope on systems
> you own or are explicitly engaged to test.

## Contents

- [Architecture](#architecture)
- [Why four engines](#why-four-engines)
- [Install](#install)
- [Quick start (no hardware)](#quick-start-no-hardware)
- [Live workflow](#live-workflow)
- [Sessions](#sessions)
- [Physical layer (no OS)](#physical-layer-no-operating-system)
- [Tool reference](#tool-reference)
- [CLI](#cli)
- [Registering the MCP server](#registering-the-mcp-server)
- [Layout](#layout)
- [Design notes](#design-notes)
- [Limitations](#limitations)
- [Tests](#tests)
- [Development](#development)
- [License](#license)

## Architecture

```
+----------------------- MCP client (agent) -----------------------+
|     session_*  processes  modules  read  scan_*  emu_*  ...      |
+---------------------------------+--------------------------------+
                                  |  stdio / JSON-RPC
+---------------------------------v--------------------------------+
|                           phantomscope                           |
|                                                                  |
|    +----------------+   +----------------+   +----------------+  |
|    | StaticEngine   |   | DynamicEngine  |   | Emulator       |  |
|    | pefile         |   | scans          |   | unicorn        |  |
|    | capstone       |   | patches        |   | step           |  |
|    | xrefs, structs |   | ptr chains     |   | watchpoints    |  |
|    +-------+--------+   +-------+--------+   +-------+--------+  |
|            |                    |                    |           |
|            +--------------------+--------------------+           |
|                                 |                                |
|                         +-------v-------+                        |
|                         | MemoryBackend |                        |
|                         +-------+-------+                        |
|                                 |                                |
|            |                    |                    |           |
|            +--------------------+--------------------+           |
|        MemProcFS             physical               mock         |
+------------+--------------------+--------------------+-----------+
             |                    |                    |
             v                    v                    v
       PCILeech FPGA       raw dump / pmem        demo target
```

## Why four engines

DMA cannot stop a thread, read a register context or single-step. So a classic
debugger is not available, and phantomscope replaces each of its jobs:

| Need | Engine | What it does |
| --- | --- | --- |
| Understand a module | **Static** | The bytes captured over DMA are a complete PE image; parse, disassemble, index, infer structs locally |
| Find a value / structure | **Dynamic** | Value scans, AOB scans, narrowing, pointer chains, snapshot diffs |
| Change something | **Dynamic** | Journaled writes with one-call restore |
| "Debug" a function | **Emulator** | Snapshot code + data, run it in Unicorn, use watchpoints and API hooks as breakpoints |
| No OS at all | **Physical** | Raw dump: physical addressing, page-table walking, PE discovery by structure |

That last row is the honest substitute for breakpoints: you *cannot* break on a
live DMA target, but you can capture the function, its arguments and its data,
then emulate it deterministically — as many times as you like.

## Install

```bash
git clone https://github.com/Absurdity233/phantomscope
cd phantomscope
python -m venv .venv
```

```powershell
# Windows — the only platform MemProcFS supports
.\.venv\Scripts\python.exe -m pip install -e ".[dev,emulate]"
```

```bash
# Linux / macOS — mock, static and physical layers work; the DMA backend does not
.venv/bin/python -m pip install -e ".[dev,emulate]"
```

`memprocfs` ships the `vmm.dll` runtime and installs on Windows only.
`unicorn` is optional: without it everything except the `emu_*` tools still
works, and those report `unavailable` instead of failing.

## Quick start (no hardware)

```powershell
.\.venv\Scripts\phantomscope.exe demo
```

The demo builds a synthetic target — a mapped PE module, a heap struct with
health/ammo/score, two threads with callstacks, symbols, handles — and walks the
whole pipeline: enumerate, read, scan, patch, restore, capture the module,
disassemble it, and emulate the entry point.

## Live workflow

First, sanity-check the device and time every backend operation:

```powershell
# against a PCILeech FPGA
.\.venv\Scripts\python.exe tools\probe_backend.py fpga
# or an offline dump
.\.venv\Scripts\python.exe tools\probe_backend.py C:\dumps\win10.raw
```

`probe_backend.py` opens the device, then reports the latency of every backend
operation (processes, modules, regions, threads, callstack, a module read,
symbolisation, kernel modules, physical map, handles). Run it before blaming the
toolkit when a tool call feels slow.

Typical numbers on a PCILeech FPGA: the first `Vmm()` initialisation takes
20–40 s while the device is probed and the target's process list is built; after
that `list_processes()` is sub-second. If the target is asleep or DMA reads
stall, MemProcFS **blocks instead of returning an error** — that is a device
state problem, not a phantomscope bug, and `probe_backend.py` shows exactly which
call is stuck.

Then start the server and drive it from an MCP client:

```powershell
phantomscope-mcp
```

```jsonc
// 1. open a session against the FPGA
{"tool": "session_open", "arguments": {"device": "fpga"}}
// 2. find and attach to a process
{"tool": "attach", "arguments": {"process": "target.exe"}}
// 3. look around
{"tool": "modules", "arguments": {}}
{"tool": "regions", "arguments": {}}
{"tool": "threads", "arguments": {}}
{"tool": "callstack", "arguments": {"tid": 1234}}
{"tool": "handles", "arguments": {"filter": "File"}}
// 4. read a struct
{"tool": "read_typed", "arguments": {"va": "0x21A00000120", "value_type": "int32"}}
// 5. find it yourself
{"tool": "scan_value", "arguments": {"value": "100", "value_type": "int32", "label": "health"}}
{"tool": "scan_next", "arguments": {"key": "health", "value": "95"}}
// 6. change it (journaled) and undo
{"tool": "write", "arguments": {"va": "0x21A00000120", "value": "250", "value_type": "int32"}}
{"tool": "patch_restore", "arguments": {"all": true}}
// 7. hand the live module to the static engine
{"tool": "capture_module", "arguments": {"module": "target.exe", "key": "target"}}
{"tool": "functions", "arguments": {"key": "target", "limit": 50}}
{"tool": "disassemble", "arguments": {"key": "target", "va": "0x7FF600001000", "function": true}}
{"tool": "xrefs_to", "arguments": {"key": "target", "va": "0x7FF600001040"}}
{"tool": "struct_layout", "arguments": {"key": "target", "va": "0x7FF600001040"}}
// 8. emulate a function out of the snapshot
{"tool": "emu_create", "arguments": {"key": "target"}}
{"tool": "emu_call", "arguments": {"key": "target", "va": "0x7FF600001040", "args": "0x21A00000120"}}
{"tool": "emu_events", "arguments": {"key": "target"}}
```

## Sessions

Each session owns its backend, static engine and emulators. Open a live FPGA and
an offline dump at the same time and their images, scans and emulators never
collide:

```jsonc
{"tool": "session_open", "arguments": {"name": "live", "device": "fpga"}}
{"tool": "session_open", "arguments": {"name": "disk", "device": "C:/dumps/win10.raw"}}
{"tool": "images", "arguments": {"session": "live"}}
```

Every static and emulation tool accepts an optional `session`. Without one, a
bare image key is resolved against whichever engine owns it, and reusing a key
across sessions is refused rather than silently overwriting. `session_close`
drops that session's images and emulators.

Static-only work (`load_file` with no session) lands in a standalone engine that
outlives any session, so `phantomscope` is usable as a plain PE analyser.

## Physical layer (no operating system)

Some targets have no usable OS view: a dump from a hibernated machine, a
pre-boot capture, a system whose kernel structures are corrupted, or a device
that only gives you physical memory. The `physical` backend assumes nothing:

```powershell
# build a synthetic dump to try it without hardware
python tools\make_demo_dump.py demo_phys.raw

phantomscope physical demo_phys.raw --capture 0x100000
```

```jsonc
{"tool": "session_open", "arguments": {"backend": "physical", "device": "demo_phys.raw"}}
{"tool": "physical_info", "arguments": {}}
{"tool": "physical_read", "arguments": {"pa": "0x100000", "size": 64}}
{"tool": "physical_images", "arguments": {}}          // PEs found by structure alone
{"tool": "physical_scan", "arguments": {"pattern": "48 83 ec 28"}}
{"tool": "translate", "arguments": {"va": "0x7ff600001000", "cr3": "0x200000"}}
{"tool": "virtual_read", "arguments": {"va": "0x7ff600001000", "size": 64, "cr3": "0x200000"}}
{"tool": "walk", "arguments": {"va": "0x7ff600000000", "size": 4096, "cr3": "0x200000"}}
{"tool": "capture_image", "arguments": {"pa": "0x100000", "key": "phys"}}
{"tool": "disassemble", "arguments": {"key": "phys", "count": 8}}
```

What the layer provides:

| Piece | File | Notes |
| --- | --- | --- |
| `PhysicalImage` | `physical/image.py` | Sparse segments (`memmap=pa,size;...`), gaps read as zeros and are counted, writes go to the file |
| `X64Pager` | `physical/paging.py` | 4- and 5-level paging, 4 KiB / 2 MiB / 1 GiB pages, present-bit aware |
| `scan_pe_images` | `physical/pescan.py` | Page-aligned `MZ` + validated headers (machine, subsystem, `SizeOfImage`) |
| `PhysicalBackend` | `physical/backend.py` | Implements `MemoryBackend`; `pid` is a physical address when 0, a CR3 otherwise |

Two honest limitations: a physical image has **no process, module, thread or
symbol list**, and `capture_image` bases the image at its PE `ImageBase` rather
than its physical address, because RVAs are relative to the load address.

## Tool reference

74 tools. Every dynamic tool needs a session; every static tool needs a loaded
image key (`images` lists them).

### Session
`session_open`, `session_list`, `session_close`, `attach`, `server_info`

### Process / module / thread
`processes`, `process_info`, `modules`, `regions`, `threads`, `callstack`,
`address_info`

`address_info` resolves a VA to its module, region, protection and symbol.

### Kernel / handles / heaps
`kernel_modules`, `kernel_processes`, `handles`, `heaps`

`handles` filters on type or name. `kernel_processes` currently delegates to the
user-mode list — a hook for a real kernel view, not one yet.

### Memory
`read`, `read_typed`, `write`, `patch_list`, `patch_restore`, `dump_region`

Every `write` is journaled and reversible; `patch_restore(all=true)` undoes the
whole session.

### Discovery
`scan_aob`, `scan_value`, `scan_next`, `scan_results`, `pointer_scan`,
`snapshot`, `diff`, `watch`

`scan_value` → `scan_next` is the narrowing loop: scan once, let the target
change, then keep only the addresses whose value still matches.

### Static
`load_file`, `capture_module`, `images`, `unload_image`, `image_summary`,
`sections`, `imports`, `exports`, `strings`, `functions`, `function_info`,
`disassemble`, `basic_blocks`, `xrefs_to`, `xrefs_from`, `callers`, `callees`,
`scan_pattern`, `rtti`, `static_read`, `static_address_info`,
`struct_layout`, `globals_touched`

`struct_layout` turns every `[rcx+0x10]` in a function into a field hypothesis —
offset, width, read/write, and the instructions that produced it. It reports
what the code *touches*, not what the struct contains, and the base is a *role*
(`arg0`, `arg1`, …) because nothing proves which object a register holds.

### Emulation
`emu_available`, `emu_create`, `emu_regs`, `emu_step`, `emu_run`, `emu_read`,
`emu_write`, `emu_watch`, `emu_events`, `emu_call`

`emu_call` runs a function with the x64 Microsoft calling convention and stops at
a return trap, so you get a `retval` without a debugger.

### Physical (no OS)
`physical_info`, `physical_map`, `physical_read`, `physical_write`,
`translate`, `virtual_read`, `virtual_write`, `walk`, `physical_images`,
`physical_scan`, `capture_image`

## CLI

```
phantomscope demo                      # hardware-free end-to-end walkthrough
phantomscope static  notepad.exe       # PE summary
phantomscope functions notepad.exe     # discovered functions
phantomscope disasm  notepad.exe 0x1400019c0 --count 20
phantomscope strings notepad.exe --contains password
phantomscope scan    notepad.exe "48 8B ?? E8"
phantomscope physical dump.raw --capture 0x100000   # raw dump, no OS
phantomscope mcp                       # MCP server on stdio
```

The CLI builds the same engines the MCP server uses, so anything reachable there
is reachable here.

## Registering the MCP server

A project-scoped [`.mcp.json`](.mcp.json) is included; point its `command` at
your checkout. To add it to your user scope instead:

```powershell
claude mcp add phantomscope --scope user -- <checkout>\.venv\Scripts\phantomscope-mcp.exe
```

Or add it by hand to `mcpServers` in `~/.claude.json`:

```json
"phantomscope": {
  "type": "stdio",
  "command": "<checkout>\\.venv\\Scripts\\phantomscope-mcp.exe",
  "args": [],
  "env": {}
}
```

## Layout

```
src/phantomscope/
  backend.py                 MemoryBackend contract + capabilities
  backends/
    memprocfs_backend.py     PCILeech FPGA / dumps / pmem / LeechAgent
    mock.py                  deterministic in-memory target
    demo.py                  synthetic PE + process used by tests and `demo`
    factory.py               create_backend()
  analysis/
    pe.py                    mapped PE image (file or DMA capture)
    disasm.py                capstone wrapper, normalised instructions
    index.py                 functions, basic blocks, xrefs, call graph
    scan.py                  strings, AOB patterns, RTTI/vtables
    structs.py               struct layout inference from memory operands
    engine.py                StaticEngine facade
  dynamic/
    engine.py                DynamicEngine: reads, patches, scans, diffs
    emulator.py              unicorn snapshot emulator
    session.py               backend + engines, named sessions
  physical/
    image.py                 sparse raw physical image
    paging.py                x86-64 page-table walking
    pescan.py                PE discovery by structure alone
    backend.py               MemoryBackend over physical memory
  mcp_server.py              MCP tools (74)
  cli.py                     command line front end
tests/                       137 tests, no hardware required
tools/probe_backend.py       live device sanity check with per-step timings
tools/make_demo_dump.py      synthetic raw dump for the physical layer
```

## Design notes

* **Mapped images everywhere.** A PE from disk and a module captured over DMA
  both become an RVA-indexed buffer, so every read, scan and disassembly path is
  identical for both. `capture_module` is the bridge between the two engines.
* **Bounded work.** Function discovery is capped by `max_instructions` (1.5M),
  scans by `MAX_SCAN_BYTES` (512 MB) and emulation by a step budget, so a tool
  call cannot hang a session.
* **Every write is reversible.** `write` records the original bytes;
  `patch_list` and `patch_restore` give you a full journal.
* **Honest capability reporting.** `MemoryBackend.caps` and the `Unavailable`
  error make it explicit when a backend cannot provide something (for example
  callstacks on a raw dump) instead of returning plausible-looking zeros.
* **Per-session state.** Each session owns its static engine and emulators, so
  two targets in one server cannot overwrite each other's images or scans.

## Limitations

* **No breakpoints on a live target.** Emulate a snapshot instead.
* **`struct_layout` is a hypothesis, not a type.** Untouched fields are
  invisible, and overlapping accesses are reported rather than merged.
* **The physical layer does not parse kernel structures.** It finds PEs by
  header and translates VAs given a CR3; it will not hand you a process list.
* **Function discovery is heuristic.** Recursive descent plus a linear sweep and
  prologue scanning; heavily virtualised or obfuscated code will be incomplete.
* **DMA reads can block.** If the target sleeps or the link stalls, MemProcFS
  blocks instead of erroring — use `probe_backend.py` to find the stuck call.
* **The live FPGA path is not covered by CI.** Tests run against the mock and
  synthetic dumps; hardware paths need a device.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q
.\.venv\Scripts\python.exe tests\mcp_smoke.py    # real stdio MCP round trip
```

Emulator tests are skipped automatically when `unicorn` is not installed.

## Development

To add a tool: implement it in the relevant engine, wrap it in `mcp_server.py`
with `@server.tool()`, and add the name to
`tests/test_mcp.py::test_tool_registry_is_complete`.

## License

MIT — see [LICENSE](LICENSE).
