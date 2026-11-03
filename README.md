# phantomscope

DMA-driven reverse engineering: static PE analysis, live memory inspection over
MemProcFS, snapshot emulation, and an MCP server that exposes all of it to an
LLM agent.

```
 ┌─────────────────── MCP client (agent) ────────────────────┐
 │  session_*  processes  modules  read  scan_*  emu_*  ...   │
 └───────────────────────────┬───────────────────────────────┘
                             │  stdio / JSON-RPC
 ┌───────────────────────────▼───────────────────────────────┐
 │                      phantomscope                          │
 │  ┌─────────────┐   ┌──────────────┐   ┌─────────────────┐ │
 │  │ StaticEngine│   │DynamicEngine │   │   Emulator      │ │
 │  │ pefile      │   │ scans/patches│   │ unicorn         │ │
 │  │ capstone    │   │ threads      │   │ step/watchpoints│ │
 │  └──────┬──────┘   └──────┬───────┘   └────────┬────────┘ │
 │         │                 │                    │          │
 │         │          ┌──────▼───────┐            │          │
 │         └─────────▶│ MemoryBackend│◀───────────┘          │
 │                    │ MemProcFS    │                       │
 │                    │ mock (demo)  │                       │
 │                    └──────┬───────┘                       │
 └───────────────────────────┼───────────────────────────────┘
                     ┌───────▼────────┐
                     │ PCILeech FPGA  │  or a memory dump / pmem
                     └────────────────┘
```

## Why two engines

DMA hardware gives you **read/write access to physical memory** — and nothing
else. There is no thread suspension, no register context, no single step. A
classic debugger is not available, so phantomscope splits the job:

| Need | Engine | Reality |
| --- | --- | --- |
| Understand a module | **Static** | The bytes captured over DMA are a complete PE image; parse, disassemble, index it locally |
| Find a value / structure | **Dynamic** | Value scans, AOB scans, narrowing, pointer chains, snapshot diffs |
| Change something | **Dynamic** | Journaled writes with one-call restore |
| "Debug" a function | **Emulator** | Snapshot the code + data, run it in Unicorn, set watchpoints and call hooks locally |
| No OS at all | **Physical** | Raw dump: physical addressing, page-table walking, PE discovery by structure |

That last row is the honest substitute for breakpoints: you *cannot* break on a
live DMA target, but you can capture the function, its arguments and its data,
then emulate it deterministically.

## Install

```powershell
cd F:\phantomscope
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,emulate]"
```

`memprocfs` ships the `vmm.dll` runtime and only installs on Windows. The
`mock` backend needs no hardware at all.

## Quick start (no hardware)

```powershell
.\.venv\Scripts\phantomscope.exe demo
```

The demo builds a synthetic target — a mapped PE module, a heap struct with
health/ammo/score, two threads with callstacks, symbols — and walks the whole
pipeline: enumerate, read, scan, patch, restore, capture the module, disassemble
it, and emulate the entry point.

## Live usage

```powershell
# first, sanity-check the device and time every stage
.\.venv\Scripts\python.exe tools\probe_backend.py fpga
# or against an offline dump
.\.venv\Scripts\python.exe tools\probe_backend.py C:\dumps\win10.raw

phantomscope-mcp
```

`probe_backend.py` opens the device, then reports the latency of every backend
operation (processes, modules, regions, threads, callstack, a module read,
symbolisation, kernel modules, physical map, handles). Use it before blaming
the toolkit when a tool call feels slow.

Typical numbers on a PCILeech FPGA: the first `Vmm()` initialisation takes
20–40 s while the device is probed and the target's process list is built;
after that `list_processes()` is sub-second. If the target is asleep or DMA
reads stall, MemProcFS blocks instead of returning an error — that is a device
state problem, not a phantomscope bug, and `probe_backend.py` shows exactly
which call is stuck.

Then in an MCP client:

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
// 8. emulate a function out of the snapshot
{"tool": "emu_create", "arguments": {"key": "target"}}
{"tool": "emu_call", "arguments": {"key": "target", "va": "0x7FF600001040", "args": "0x21A00000120"}}
{"tool": "emu_events", "arguments": {"key": "target"}}
```

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

### Session
`session_open`, `session_list`, `session_close`, `attach`, `server_info`

### Process / module / thread
`processes`, `process_info`, `modules`, `regions`, `threads`, `callstack`,
`address_info`

### Memory
`read`, `read_typed`, `write`, `patch_list`, `patch_restore`, `dump_region`

### Discovery
`scan_aob`, `scan_value`, `scan_next`, `scan_results`, `pointer_scan`,
`snapshot`, `diff`, `watch`

### Static
`load_file`, `capture_module`, `images`, `unload_image`, `image_summary`,
`sections`, `imports`, `exports`, `strings`, `functions`, `function_info`,
`disassemble`, `basic_blocks`, `xrefs_to`, `xrefs_from`, `callers`, `callees`,
`scan_pattern`, `rtti`, `static_read`, `static_address_info`,
`struct_layout`, `globals_touched`

### Emulation
`emu_available`, `emu_create`, `emu_regs`, `emu_step`, `emu_run`, `emu_read`,
`emu_write`, `emu_watch`, `emu_events`, `emu_call`

### Physical (no OS)
`physical_info`, `physical_map`, `physical_read`, `physical_write`,
`translate`, `virtual_read`, `virtual_write`, `walk`, `physical_images`,
`capture_image`

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

## Registering the MCP server

A project-scoped [`.mcp.json`](.mcp.json) is included. To add it to your user
scope instead:

```powershell
claude mcp add phantomscope --scope user -- F:\phantomscope\.venv\Scripts\phantomscope-mcp.exe
```

Or add it by hand to `mcpServers` in `~/.claude.json`:

```json
"phantomscope": {
  "type": "stdio",
  "command": "F:\phantomscope\.venv\Scripts\phantomscope-mcp.exe",
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
  mcp_server.py              MCP tools (57)
  cli.py                     command line front end
tests/                       127 tests, no hardware required
tools/probe_backend.py       live device sanity check with per-step timings
tools/make_demo_dump.py      synthetic raw dump for the physical layer
```

## Design notes

* **Mapped images everywhere.** A PE from disk and a module captured over DMA
  both become an RVA-indexed buffer, so every read, scan and disassembly path is
  identical for both. `capture_module` is the bridge between the two engines.
* **Bounded work.** Function discovery is capped by `max_instructions`
  (1.5M), scans by `MAX_SCAN_BYTES` (512 MB) and emulation by a step budget, so
  a tool call cannot hang a session.
* **Every write is reversible.** `write` records the original bytes; `patch_list`
  and `patch_restore` give you a full journal, including `all=true`.
* **Honest capability reporting.** `MemoryBackend.caps` and the `Unavailable`
  error make it explicit when a backend cannot provide something (for example
  callstacks on a raw dump) instead of returning plausible-looking zeros.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q
.\.venv\Scripts\python.exe tests\mcp_smoke.py    # real stdio MCP round trip
```

Emulator tests are skipped automatically when `unicorn` is not installed.
