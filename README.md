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
# A PCILeech FPGA (default device)
phantomscope-mcp

# an offline dump
python -m phantomscope.mcp_server   # then session_open(device="C:/dumps/win10.raw")
```

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
`scan_pattern`, `rtti`, `static_read`, `static_address_info`

### Emulation
`emu_available`, `emu_create`, `emu_regs`, `emu_step`, `emu_run`, `emu_read`,
`emu_write`, `emu_watch`, `emu_events`, `emu_call`

## CLI

```
phantomscope demo                      # hardware-free end-to-end walkthrough
phantomscope static  notepad.exe       # PE summary
phantomscope functions notepad.exe     # discovered functions
phantomscope disasm  notepad.exe 0x1400019c0 --count 20
phantomscope strings notepad.exe --contains password
phantomscope scan    notepad.exe "48 8B ?? E8"
phantomscope mcp                       # MCP server on stdio
```

## Registering the MCP server

A project-scoped [`.mcp.json`](.mcp.json) is included. To add it to your user
scope instead:

```powershell
claude mcp add phantomscope --scope user -- F:\phantomscope\.venv\Scripts\phantomscope-mcp.exe
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
    engine.py                StaticEngine facade
  dynamic/
    engine.py                DynamicEngine: reads, patches, scans, diffs
    emulator.py              unicorn snapshot emulator
    session.py               backend + engines, named sessions
  mcp_server.py              MCP tools (57)
  cli.py                     command line front end
tests/                       76 tests, no hardware required
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
