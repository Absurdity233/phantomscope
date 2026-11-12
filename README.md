# phantomscope

**DMA-driven reverse engineering.** Static PE analysis, live memory inspection
over MemProcFS, snapshot emulation, and an MCP server that exposes all of it to
an LLM agent.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](#license)
[![Tests](https://img.shields.io/badge/tests-324%20passing-brightgreen.svg)](#tests)
[![MCP tools](https://img.shields.io/badge/MCP%20tools-115-informational.svg)](#tool-reference)
[![Windows](https://img.shields.io/badge/DMA%20backend-Windows-lightgrey.svg)](#install)

---

## What this is

DMA hardware (a PCILeech FPGA, or a memory dump) gives you read/write access to
physical memory — and nothing else. No thread suspension, no register context,
no single step, no breakpoints. phantomscope is built around that constraint: it
splits "understand and change a target" into four engines, each honest about
what it can actually do, and exposes the whole thing as **115 MCP tools** so an
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
- [Reading real code](#reading-real-code)
- [Triage and matching](#triage-and-matching)
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
|    | pseudo-C, hash |   |                |   | import stubs   |  |
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
| Read a function | **Static** | Pseudo-C from the CFG (dominators, natural loops, conditions), import and string resolution, persistent names |
| Recognise code | **Static** | Normalised function hashes, similarity search, cross-build diffing |
| "Debug" a function | **Emulator** | Snapshot code + data, run it in Unicorn, use watchpoints and API hooks as breakpoints; IAT stubs make imported calls return |
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

## Reading real code

`disassemble` tells you what the bytes are. These tools tell you what they
*mean*, and they all read the same image the rest of the server uses — a PE from
disk or a module captured over DMA.

```python
decompile(key="game", va="0x7ff6a1b020")        # pseudo-C for one function
```

```
// int32_t sub_1020(int64_t arg0)
// 0x7ff600001020 .. 0x7ff600001031  3 block(s), 0 loop(s)
int32_t sub_1020(int64_t arg0) {
    if (arg0 > 5) {
        eax = 0x64;  // mov eax, 0x64
        return eax;
    } else {
        eax = 7;  // mov eax, 7
        return eax;
    }
}
```

How it gets there, and what it refuses to fake:

* **Structure from the CFG, not from line order.** Basic blocks, dominators and
  post-dominators, natural loops from back edges, if/else joins. Loops become
  `while (cond)` or `while (1) { ... if (exit) break; }`; irreducible graphs fall
  back to `goto` and say so in `notes`.
* **Conditions from the flags.** `cmp` / `test` are tracked, and a branch after
  `dec ecx` becomes `ecx == 0` instead of a stale comparison. Unrecoverable
  conditions stay visible as `cc_<suffix>` rather than being invented.
* **Names from where they exist.** `arg0..arg3` for incoming registers (degraded
  to the plain register once it is overwritten), `module!Api` for import calls and
  import thunks, `g_<rva>` for RIP-relative globals, the string literal itself for
  `lea rcx, [rip+...]`.
* **Every line keeps its instruction** as a trailing comment, so the output can be
  checked against `disassemble` instead of trusted. Idioms with no C spelling get
  an intrinsic form (`__ror(x, 0xa)`, `__rep_stosb(rdi, rsi, rcx)`,
  `edx:eax = __rdtsc()`, a one-line `lock cmpxchg` exchange) and only what is
  genuinely unmodelled — SSE shifts, exotic vector ops — appears as
  `__asm__(...)` rather than vanishing.
* **`confidence` is computed, not asserted.** Unreachable blocks, irreducible
  edges and unmodelled instructions lower it; `notes` says which.

Names are worth the keystrokes:

```
rename_function(key="game", va="0x7ff6a1b020", name="decrypt_config")
set_comment(key="game", va="0x7ff6a1b024", text="key length is checked here")
annotations(key="game")
```

From then on `functions`, `function_info`, `address_info`, `decompile` and
`disassemble` all use that name, and the store is written to
`<file>.phantomscope.json` next to a PE loaded from disk (in-memory captures keep
their names for the session only — there is no local file to sit next to).

Two more shortcuts into an unknown function:

```
api_calls(key="game", va="0x7ff6a1b020")   # kernel32!CreateFileW, advapi32!RegSetValue
string_xrefs(key="game", contains="expired")   # the strings and the code that reads them
```

`api_calls` resolves `call [rip+iat]` *and* the `mov reg,[iat]; call reg` thunk
form, which is most of what a stripped binary gives you.

## Triage and matching

Before reading code, decide what you are holding — and after a rebuild, find out
what changed.

```
packing_report(key="game")            # entropy, RWX sections, no imports, TLS callbacks
crypto_constants(key="game")          # AES S-box, CRC-32 table, SHA/MD5 IVs, TEA delta
search_immediates(key="game", value="0x1e")   # who tests against 30

fingerprint(key="game", va="0x7ff6a1b020")    # normalised hash + constants
find_similar(key="game", va="0x7ff6a1b020")   # the other copies of that routine
diff_images(left="game_v1", right="game_v2")  # identical / similar / removed / added
```

`packing_report` returns evidence with weights and a 0-10 score, not a verdict
from nowhere; `crypto_constants` says a table is *present*, not that the function
is AES; `fingerprint` abstracts branch targets and immediates so the same function
hashes the same at another base (the immediates are kept separately in
`constants`), and `diff_images` turns a whole rebuild into a short list of
functions that actually changed.

`emu_stubs` is the fourth piece: a snapshot has the image, not `kernel32`, so
`emu_call` on real code would fault on the first `call [iat]`. `emu_stubs`
rewrites every IAT slot to a generated `mov eax, imm; ret` stub and logs each hit
with its argument registers — and `returns="GetTickCount=0x64"` drives the value,
which is how a check gets taken down the success path without patching anything:

```
emu_create(key="game", stubs=True)
emu_call(key="game", va="0x7ff6a1b020", args="0x1,0x0")
emu_calls(key="game")     # kernel32!Sleep(0xa), ...
```
## Tool reference

115 tools. Every dynamic tool needs a session; every static tool needs a loaded
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
`scan_aob`, `scan_value`, `scan_next`, `scan_results`, `scan_strings`,
`pointer_scan`, `snapshot`, `diff`, `trace_changes`, `trace_value`

`scan_value` → `scan_next` is the narrowing loop: scan once, let the target
change, then keep only the addresses whose value still matches.

`scan_strings` searches *live* memory, which is the only place a URL built after a
redirect, a decrypted key or a heap-assembled JSON payload exists. `encoding="both"`
covers ASCII and UTF-16LE, and the wide walk tries both byte alignments — a heap
buffer is not 2-aligned relative to the region you happen to read, so an even-only
walk silently misses about half of all wide strings.

DMA cannot set a memory breakpoint: nothing stops, so nothing can be inspected
mid-instruction. The substitute is sampling. `trace_changes` polls a range a few
times and reports every byte that moved, how many samples caught a new value, the
bit flips, whether the surrounding value only increased, and the same bytes read
as `int32`/`uint32`/`float`/`int64`/`uint64`/`double` — usually enough to tell a
flag from a counter from a timer, without ever pausing the target.
`trace_value` is the single-value form (`series`, `min`, `max`, `deltas`).

### Live structures
`read_object`, `read_array`, `infer_struct`, `detect_container`,
`expand_container`, `resolve_pointer_chain`, `pointer_chain_replay`,
`snapshot_module`, `diff_module`

These are the "cheat table" operations, done honestly:

- `read_object` dumps an object as hexdump + aligned qwords with pointer validity
  (`points_to`, `target_module`) + string runs, and decodes explicit fields from
  `"0x0:int32,0x8:pointer,0x10:char[16]"`.
- `read_array` walks `count` objects `stride` apart, or with `follow=true` an
  `Entity**` table, reading `object_size` bytes at each target.
- `infer_struct` derives a layout from sampled *values*: a qword that is a mapped
  address in every sample is a pointer, one whose high dword is always zero is an
  `int32`, one that is zero in every sample is padding. `varies` marks fields that
  differ between objects, `alternatives` keeps the readings it cannot rule out, and
  `c_struct` prints a declaration you can paste into a header.
- `detect_container` says whether the bytes are a `std::vector<T>` (`{begin, end,
  capacity}`), an Unreal `TArray<T>` (`{data, count, capacity}`), a `std::string`
  (SSO or heap), or a bare `{ptr, count, capacity}` — as *hypotheses checked
  against the data*, each with its evidence, all the ones that fit, and the
  strongest one marked `primary`. `expand_container` then reads the elements.
- `resolve_pointer_chain` walks `game.exe+0x1a2b` + `"0x10,0x38,0x8"` and reports
  every hop with the module/region it landed in, the final typed value, and a
  `template` you can replay later. A broken hop names the level and the address
  instead of returning a plausible zero.
- `pointer_chain_replay` re-runs chains from `pointer_scan` after a restart and
  keeps the ones that still resolve; chains not anchored in a module are refused
  with the reason, because they cannot survive a relaunch.
- `snapshot_module` / `diff_module` compare a whole module against a baseline, so
  "the config table was decrypted in place" becomes a byte diff.

### Emulation
`emu_available`, `emu_create`, `emu_regs`, `emu_step`, `emu_run`, `emu_read`,
`emu_write`, `emu_watch`, `emu_events`, `emu_call`, `emu_stubs`, `emu_calls`,
`emu_stub_list`, `emu_trace`, `emu_coverage`, `emu_reached`, `emu_faults`,
`emu_close`

`emu_call` runs a function with the x64 Microsoft calling convention and stops at
a return trap, so you get a `retval` without a debugger. `emu_stubs` is what makes
that work on code that calls imports: every IAT slot is redirected to a generated
`mov eax, imm; ret` stub whose return value you choose, and `emu_calls` replays
what the code called and with which arguments.

Snapshot emulation replaces the debugger features DMA cannot provide, so it also
answers the questions a debugger would: `emu_create(trace=true)` (or `emu_trace`)
records executed instructions and taken edges, `emu_coverage` returns unique
instructions, hot spots and `forks` — every address with more than one successor,
i.e. the branch decisions the run actually made, which is the cheap answer to "did
the check pass" and "which switch case ran". `emu_reached` splits a list of
addresses into executed and not executed. `emu_faults` reports unmapped reads,
writes and fetches with rip, address and size — and a fault is reported as the
run's `reason` instead of a misleading `budget_exhausted`, so "it crashed on
`[rax+0x10]` with `rax=0xdead0000`" is a single tool call.

### Static
`load_file`, `capture_module`, `export_module`, `save_image`, `images`,
`unload_image`, `image_summary`, `sections`, `imports`, `exports`, `strings`,
`functions`, `function_info`, `disassemble`, `basic_blocks`, `xrefs_to`,
`xrefs_from`, `callers`, `callees`, `scan_pattern`, `rtti`, `static_read`,
`static_address_info`, `struct_layout`, `globals_touched`

`export_module` and `save_image` are the last mile of unpacking. A module captured
over DMA is RVA-indexed, so writing that buffer straight to disk produces a file
whose section headers no longer describe where the bytes are — IDA, Ghidra and
pefile all reject it. Both tools demap it first: headers stay, each section moves
from its virtual address to its declared raw offset. `raw=True` keeps the mapped
layout when you want a byte-exact capture instead.

### Pseudo-C and naming
`decompile`, `rename_function`, `set_comment`, `annotations`,
`clear_annotations`

`decompile` lifts one function to pseudo-C and reports `confidence` plus the
reasons it is not higher; annotations make names stick across tools and across
process restarts (JSON sidecar next to a PE loaded from disk).

### Patching a static image
`patch_apply`, `static_patch_list`, `static_patch_restore`

The static twin of `write`: patch the image (where the code you disassembled
actually lives), then `save_image` to demap it into a working file. Every patch
keeps its original bytes, the cached function index for that image is dropped so
`disassemble` and `decompile` show the new bytes immediately, and
`static_patch_restore(all=true)` puts everything back.

### Import and string references
`api_calls`, `api_sites`, `find_api`, `string_xrefs`

`api_calls` answers "what does this function talk to" — the fastest classifier of
an unknown routine — and `string_xrefs` answers "who reads this string".

### Similarity, matching and triage
`fingerprint`, `find_similar`, `match_functions`, `diff_images`,
`packing_report`, `crypto_constants`, `search_immediates`

Normalised function hashes match code across addresses and builds;
`diff_images` turns a rebuild into identical / similar / removed / added lists.

`struct_layout` turns every `[rcx+0x10]` in a function into a field hypothesis —
offset, width, read/write, and the instructions that produced it. It reports
what the code *touches*, not what the struct contains, and the base is a *role*
(`arg0`, `arg1`, …) because nothing proves which object a register holds.

`live_struct_layout` closes that gap by running the live half at the same time.
Neither view is a struct on its own: the code knows which offsets exist and at what
width, the memory knows what is *in* them but also reports the padding between
them. Merged, every offset is confirmed by code *and* typed by data, padding is
dropped, a dword that reads as a sane float in every sample is declared `float`
(a `mov eax, [rcx+0x10]` does not stop 10.0f being a coordinate), adjacent floats
are grouped into a `float pos_x[3]`, and offsets seen in only one of the two sides
are reported as `code_only_offsets` / `data_only_offsets` rather than silently
dropped. Names encode evidence — `ptr_`, `text_`, `state_`, `const_` — never a guess
like `health`, because a wrong guess stops you checking.

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
phantomscope decompile notepad.exe 0x1400019c0      # pseudo-C for one function
phantomscope apis    notepad.exe --needle Reg      # imports and their call sites
phantomscope triage  notepad.exe                   # packing score, crypto tables
phantomscope immediates notepad.exe 0x1e           # who tests against 30
phantomscope diff    build_a.dll build_b.dll       # what changed between builds
phantomscope physical dump.raw --capture 0x100000   # raw dump, no OS
phantomscope mcp                       # MCP server on stdio
```

The live commands share one target selector — `--process NAME` (substring) or
`--pid PID`, plus `--kind`/`--device` for the backend:

```
phantomscope chain  --process target.exe game.exe+0x1a2b "0x10,0x38,0x8" --value-type int32
phantomscope object --process target.exe 0x21A00000120 --fields "0x0:int32,0x10:char[16]"
phantomscope array  --process target.exe 0x21B00000000 --stride 0x20 --count 16 --follow
phantomscope infer  --process target.exe 0x21A00000120 --count 8 --stride 0x20 --align 4
phantomscope container --process target.exe 0x21A00000180 --expand
phantomscope trace  --process target.exe 0x21A00000100 0x40 --samples 12
phantomscope memstrings --process target.exe "https://" --encoding both
phantomscope dumpmodule --process target.exe target.exe unpacked.exe
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
    gametarget.py            synthetic shooter with a live tick (motion-dependent tests)
    factory.py               create_backend()
  analysis/
    pe.py                    mapped PE image (file or DMA capture)
    disasm.py                capstone wrapper, normalised instructions
    index.py                 functions, basic blocks, xrefs, call graph
    scan.py                  strings, AOB patterns, RTTI/vtables
    structs.py               struct layout inference from memory operands
    pseudo.py                pseudo-C recovery (CFG, loops, conditions, names)
    apis.py                  import resolution: call sites and thunks
    fingerprint.py           normalised function hashes, similarity, diffing
    detect.py                packing triage, crypto constants, immediates
    layout_map.py            merges static field accesses with live types
    annotations.py           persistent names/comments (JSON sidecar)
    engine.py                StaticEngine facade
  dynamic/
    engine.py                DynamicEngine: reads, patches, scans, diffs
    pointer.py               pointer-chain resolution and replay
    structures.py            live objects, arrays, layout inference, containers
    trace.py                 sampled change tracing (the no-breakpoint substitute)
    emulator.py              unicorn snapshot emulator + coverage and faults
    session.py               backend + engines, named sessions
  physical/
    image.py                 sparse raw physical image
    paging.py                x86-64 page-table walking
    pescan.py                PE discovery by structure alone
    backend.py               MemoryBackend over physical memory
  mcp_server.py              MCP tools (115)
  cli.py                     command line front end
tests/                       324 tests, no hardware required
tools/probe_backend.py       live device sanity check with per-step timings
tools/make_demo_dump.py      synthetic raw dump for the physical layer
skills/                      6 scenario skills (see below)
```

## Skills

`skills/` holds six agent skills, each a workflow rather than a feature list:
which tools in which order, what the output means, and where the approach stops
working. They are plain `SKILL.md` files with frontmatter, so any client that
reads the Claude skill format can use them directly.

| Skill | Scenario |
|---|---|
| `phantomscope-offset-dump` | scan → pointer chain → replay → a reusable `base+offsets` template |
| `phantomscope-live-struct` | turn live memory into structs and containers without pausing the target |
| `phantomscope-encrypted-coords` | separate plaintext from ciphertext, find the routine, reverse the key in the emulator |
| `phantomscope-unpack-dump` | decide if a binary is packed, wait for it to unpack itself, dump it demapped |
| `phantomscope-license-crack` | locate a licence check, read the branch actually taken, patch and roll back |
| `phantomscope-emu-triage` | what a function does under given inputs: return value, branch forks, API calls, faults |

Every tool name and argument in them is checked against the live registry, so a
skill cannot drift into calling something that does not exist. To install them
for the current user:

```powershell
Copy-Item skills\phantomscope-* "$env:USERPROFILE\.claude\skills\" -Recurse -Force
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
* **Emulators are closed, not dropped.** Unicorn keeps a native engine per
  instance; `emu_create` closes the previous one for a key because deferring the
  release to the collector can make it run inside a later `mem_map` and fault
  there. `Emulator.close()` (or `with emulator_for(...)`) makes it explicit.

## Limitations

* **No breakpoints on a live target.** Emulate a snapshot instead. Sampling with
  `trace_changes` tells you *what* changed and how often, never *which
  instruction* wrote it — pinning that down needs a snapshot under the emulator.
* **`struct_layout` and `infer_struct` are hypotheses, not types.** Untouched
  fields are invisible, overlapping accesses are reported rather than merged, and
  an integer that happens to look like a pointer cannot be ruled out from one
  sample — which is why `infer_struct` wants `count=` and keeps `alternatives`.
* **A container's element size is not in the memory.** A `std::vector<T>` stores a
  byte span and nothing else; `detect_container` infers the size from the pointer
  rhythm inside the elements and reports `element_size_source` (`explicit`,
  `pointer_rhythm` or `alignment`) so a guess is never quoted as a fact.
* **`decompile` is a readability tool, not a compiler.** It recovers control flow
  and names, not types: stack slots stay `[rbp-0x38]`, an unknown condition shows
  as `cc_<suffix>`, and SSE/string instructions appear as `__asm__(...)`. Read it
  next to `disassemble`, which is why every line carries its instruction.
* **A fingerprint is not an identity proof.** A normalised hash matches the same
  shape; two unrelated tiny functions can share it. Treat a `1.0` as "same code",
  a partial score as "worth reading".
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
