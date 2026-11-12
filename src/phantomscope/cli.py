"""Command line front end: ``phantomscope <command> ...``.

Examples
--------
    phantomscope sessions                 list sessions of a running MCP server?
    phantomscope demo                     run every capability against the mock target
    phantomscope static notepad.exe       print a PE summary
    phantomscope functions notepad.exe    list discovered functions
    phantomscope disasm notepad.exe 0x1400019c0 --count 20
    phantomscope mcp                      run the MCP server on stdio

The CLI is deliberately thin: it builds the same engines the MCP server uses,
so anything reachable here is reachable from an MCP client and vice versa.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from . import __version__
from .analysis.engine import StaticEngine
from .backends.factory import create_backend
from .dynamic.engine import DynamicEngine
from .dynamic.emulator import emulator_available, emulator_for
from .errors import PhantomError
from .utils import human_size, parse_address


def _print(payload: Any) -> None:
    print(json.dumps(payload, indent=2, default=str, ensure_ascii=False))


def _summary_table(image) -> None:
    data = image.summary()
    print(f"file       : {data['path']}")
    print(f"arch       : {data['arch']}  base {data['base']}  entry {data['entry']}")
    print(f"size       : {data['image_size']} bytes ({human_size(data['image_size'])})")
    print(f"compiled   : {data.get('compile_time')}")
    print(f"pdb        : {data.get('pdb_path')}")
    print(f"protection : {', '.join(data['security_flags']) or 'none'}"
          f"  signed={data['signed']}  rich={data['rich_header']}")
    print(f"imports    : {data['import_count']} from {data['import_module_count']} modules")
    print(f"exports    : {data['export_count']}")
    print("sections   :")
    for section in data["sections"]:
        flags = "".join(
            [
                "r" if section.get("readable", True) else "-",
                "w" if section.get("writable") else "-",
                "x" if section.get("executable") else "-",
            ]
        )
        print(
            f"  {section['name']:<10} {section['va']:#014x} "
            f"vsize={section['vsize']:#08x} {flags} entropy={section.get('entropy')}"
        )


def cmd_static(args: argparse.Namespace) -> int:
    engine = StaticEngine()
    image = engine.load_file(args.path, key="image")
    if args.json:
        _print(engine.summary("image"))
        return 0
    _summary_table(image)
    return 0


def cmd_functions(args: argparse.Namespace) -> int:
    engine = StaticEngine()
    engine.load_file(args.path, key="image")
    rows = engine.functions("image", limit=args.limit)
    for row in rows:
        name = row.get("name") or ""
        print(f"{row['va']:#014x}  {row.get('size') or 0:#8x}  {row.get('source') or '':<10} {name}")
    return 0


def cmd_disasm(args: argparse.Namespace) -> int:
    engine = StaticEngine()
    engine.load_file(args.path, key="image")
    va = parse_address(args.va) if args.va else None
    rows = engine.disassemble("image", va, count=args.count, function=args.function)
    for row in rows:
        comment = f"  ; {row['comment']}" if row.get("comment") else ""
        print(f"{row['va']:#014x}  {row['bytes']:<24} {row['text']}{comment}")
    return 0


def cmd_strings(args: argparse.Namespace) -> int:
    engine = StaticEngine()
    engine.load_file(args.path, key="image")
    needle = args.contains.lower() if args.contains else None
    for item in engine.strings("image", limit=args.limit):
        if needle and needle not in item["text"].lower():
            continue
        print(f"{item['va']}  {item['encoding']:<5} {item['text']}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    engine = StaticEngine()
    engine.load_file(args.path, key="image")
    for hit in engine.scan("image", args.pattern, limit=args.limit):
        print(f"{hit['va']}  {hit.get('preview', '')}")
    return 0


def cmd_decompile(args: argparse.Namespace) -> int:
    """Print pseudo-C for one function (or for every function)."""
    engine = StaticEngine()
    engine.load_file(args.path, key="image")
    targets = [parse_address(args.va)] if args.va else [
        row["va"] for row in engine.functions("image", limit=args.limit)
    ]
    for va in targets:
        try:
            result = engine.decompile("image", va)
        except PhantomError as exc:
            print(f"// {va:#x}: {exc}", file=sys.stderr)
            continue
        if args.json:
            _print(result)
            continue
        print(result["text"])
        print()
    return 0


def cmd_apis(args: argparse.Namespace) -> int:
    """List imported APIs and the functions that call them."""
    engine = StaticEngine()
    engine.load_file(args.path, key="image")
    rows = engine.api_calls("image")
    if args.needle:
        needle = args.needle.lower()
        rows = [row for row in rows if needle in row["api"].lower()]
    for row in rows:
        print(f"{row['api']:<48} {row['count']:>3} call(s) in "
              f"{', '.join(row['functions'][:4])}")
    if not rows:
        print("no resolved API references (packed, or no import table)",
              file=sys.stderr)
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    """Packing score, crypto constants and overlay information."""
    engine = StaticEngine()
    engine.load_file(args.path, key="image")
    report = engine.packing_report("image")
    print(f"score    : {report['score']}/10  ({report['verdict']})")
    print(f"code     : {report['functions']} function(s) in {report['code_kib']} KiB")
    print(f"imports  : {report['imports']} from {report['import_modules']} module(s)")
    for finding in report["findings"]:
        print(f"  [{finding['weight']}] {finding['finding']}: {finding['detail']}")
    constants = engine.crypto_constants("image")
    if constants:
        print("crypto   :")
        for hit in constants:
            print(f"  {hit['va']}  {hit['name']:<18} {hit['description']}")
    return 0


def cmd_immediates(args: argparse.Namespace) -> int:
    """Find where a constant is used (code immediates and stored data)."""
    engine = StaticEngine()
    engine.load_file(args.path, key="image")
    result = engine.search_immediates("image", parse_address(args.value),
                                      width=args.width, limit=args.limit)
    print(f"{result['value']} ({result['width']} bytes): "
          f"{result['counts']['code']} code, {result['counts']['data']} data")
    for row in result["code"]:
        print(f"  code {row['va']}  {row['function']}  {row['text']}")
    for row in result["data"]:
        print(f"  data {row['va']}  {row['section']}")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    """Structural diff of two builds (identical / similar / removed / added)."""
    engine = StaticEngine()
    engine.load_file(args.left, key="left")
    engine.load_file(args.right, key="right")
    result = engine.diff_images("left", "right", min_similarity=args.min_similarity)
    print(json.dumps(result["counts"], indent=2))
    for row in result["similar"]:
        print(f"  changed {row['left']} -> {row['right']}  "
              f"similarity={row['similarity']}  {row['left_size']}->{row['right_size']} bytes")
    for row in result["removed"]:
        print(f"  removed {row['left']}  ({row['size']} bytes)")
    for row in result["added"]:
        print(f"  added   {row['right']}  ({row['size']} bytes)")
    return 0


def cmd_physical(args: argparse.Namespace) -> int:
    """Inspect a raw physical dump with no OS assumptions."""
    from .physical import PhysicalBackend

    backend = PhysicalBackend(
        device=args.path,
        options=[f"memmap={args.memmap}"] if args.memmap else None,
        name="physical",
    )
    backend.open()
    try:
        if args.cr3:
            backend.set_cr3(parse_address(args.cr3))
        info = backend.info()
        print(f"file     : {info['path']}")
        print(f"size     : {info['file_size']:#x}  mapped {info['mapped_bytes']:#x}"
              f"  max {info['max_address']}")
        for segment in info["segments"]:
            print(f"  segment  pa={segment['pa']} size={segment['size']}"
                  f" file={segment['file_offset']}")
        if backend.cr3:
            print(f"cr3      : {hex(backend.cr3)}")

        images = backend.images(limit=args.limit)
        print(f"\nPE images: {len(images)} found by structure alone")
        for hit in images:
            print(f"  {hit.pa:#012x}  {hit.arch:<5} size={hit.size:#08x}"
                  f" entry={hit.entry_rva:#06x} sections={hit.sections}"
                  f" subsystem={hit.subsystem}")

        if args.capture:
            target = parse_address(args.capture)
            payload, base_va, hit = backend.capture_image(
                target, base_va=parse_address(args.base) if args.base else None
            )
            engine = StaticEngine()
            engine.load_capture("captured", payload, base_va)
            summary = engine.summary("captured")
            print(f"\ncaptured : {summary['arch']} base={summary['base']}"
                  f" entry={summary['entry']} size={summary['image_size']:#x}")
            for insn in engine.disassemble("captured", None, count=args.count):
                print(f"  {insn['va']:#x}  {insn['text']}")
    finally:
        backend.close()
    return 0


def _live_target(args: argparse.Namespace):
    """Attach to a live target and resolve the pid once for the ``live`` commands.

    The dynamic subcommands all need the same three things - a backend, an engine
    and a pid - so they share this.  ``--process`` matches a name substring because
    nobody types the full image name from memory.
    """
    from .errors import InvalidArgument

    backend = create_backend(args.kind, device=args.device or "fpga", name="cli")
    backend.open()
    dynamic = DynamicEngine(backend)
    if args.pid:
        return backend, dynamic, int(args.pid)
    needle = (args.process or "").strip().lower()
    if not needle:
        backend.close()
        raise InvalidArgument("pass --process NAME or --pid PID")
    matches = [row for row in dynamic.list_processes() if needle in row["name"].lower()]
    if not matches:
        backend.close()
        raise InvalidArgument(f"no process matching {args.process!r}")
    return backend, dynamic, matches[0]["pid"]


def cmd_chain(args: argparse.Namespace) -> int:
    """Resolve a pointer path and print every hop."""
    backend, dynamic, pid = _live_target(args)
    try:
        offsets = [parse_address(piece) for piece in args.offsets.replace(",", " ").split()]
        result = dynamic.resolve_pointer_chain(pid, args.base, offsets,
                                               value_type=args.value_type or None,
                                               read_size=int(args.read_size or 0))
        print(f"path      : {result['base']} + {', '.join(result['offsets']) or '(none)'}")
        for level in result["levels"]:
            where = level.get("module") or level.get("region_base") or "?"
            print(f"  [{level['level']}] {level['at']}  in {where}"
                  f"  -> {level.get('pointer', '(value)')}")
        print(f"address   : {result['address']}")
        if "value" in result:
            print(f"value     : {result['value']} ({result['type']})")
        elif "hex" in result:
            print(f"bytes     : {result['hex']}")
        print(f"template  : base={result['template']['base']}"
              f" offsets={result['template']['offsets']}")
    finally:
        backend.close()
    return 0


def cmd_object(args: argparse.Namespace) -> int:
    """Dump one object without leaving the terminal."""
    backend, dynamic, pid = _live_target(args)
    try:
        result = dynamic.read_object(pid, dynamic.reparse(pid, args.va), int(args.size),
                                     fields=args.fields or None)
        print(result["hexdump"])
        for entry in result["strings"]:
            print(f"  string {entry['offset']}: {entry['text']!r}")
        for field in result.get("fields", []):
            print(f"  field  {field['offset']} {field['type']}: "
                  f"{field.get('value', field.get('error'))}")
        if args.json:
            _print(result)
    finally:
        backend.close()
    return 0


def cmd_array(args: argparse.Namespace) -> int:
    """Read ``count`` objects ``stride`` bytes apart."""
    backend, dynamic, pid = _live_target(args)
    try:
        result = dynamic.read_array(pid, dynamic.reparse(pid, args.base), int(args.stride),
                                    int(args.count), fields=args.fields or None,
                                    follow=args.follow, object_size=int(args.object_size),
                                    limit=int(args.limit))
        for entry in result["objects"]:
            detail = entry.get("error")
            if detail is None and entry.get("fields"):
                detail = ", ".join(f"{f['offset']}={f.get('value')}" for f in entry["fields"])
            elif detail is None:
                detail = entry.get("hex", "")
            print(f"  [{entry['index']:>3}] {entry['va']}  {detail}")
        print(f"stride={result['stride']} returned={result['returned']}"
              f" truncated={result['truncated']}")
    finally:
        backend.close()
    return 0


def cmd_infer(args: argparse.Namespace) -> int:
    """Infer a live structure layout and print a C declaration."""
    backend, dynamic, pid = _live_target(args)
    try:
        result = dynamic.infer_struct(pid, dynamic.reparse(pid, args.va), int(args.size),
                                      stride=int(args.stride) or None, count=int(args.count),
                                      align=int(args.align))
        print(result["c_struct"])
        for field in result["fields"]:
            line = (f"  {field['offset']} {field['type']:<10} confidence={field['confidence']}"
                    f" varies={field.get('varies')}")
            if field.get("value") is not None:
                line += f" value={field['value']}"
            if field.get("points_to"):
                line += f" -> {field['points_to']}"
            print(line)
            for alternative in field.get("alternatives", []):
                print(f"      or {alternative}")
        for note in result["notes"]:
            print(f"  note: {note}")
    finally:
        backend.close()
    return 0


def cmd_container(args: argparse.Namespace) -> int:
    """Detect a container layout and optionally list its elements."""
    backend, dynamic, pid = _live_target(args)
    try:
        va = dynamic.reparse(pid, args.va)
        if args.expand:
            result = dynamic.expand_container(pid, va,
                                              element_size=int(args.element_size) or None,
                                              fields=args.fields or None,
                                              limit=int(args.limit))
            for entry in result.get("elements", []):
                detail = ", ".join(f"{f['offset']}={f.get('value')}"
                                   for f in entry.get("fields", [])) or entry.get("hex", "")
                print(f"  {entry['va']}  {detail}")
            print(f"elements : {result.get('element_count', 0)}"
                  f" of {result.get('primary', {}).get('count')}")
            return 0
        result = dynamic.detect_container(pid, va,
                                          element_size=int(args.element_size) or None)
        for candidate in result["candidates"]:
            print(f"  {candidate['kind']:<32} confidence={candidate['confidence']}"
                  f" count={candidate.get('count')}"
                  f" element={candidate.get('element_size')}"
                  f" ({candidate.get('element_size_source', 'n/a')})")
            print(f"    {candidate['evidence']}")
        if not result["candidates"]:
            print("  no container layout fits; try the object subcommand")
    finally:
        backend.close()
    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    """Poll a range and report what moved (the memory-breakpoint substitute)."""
    backend, dynamic, pid = _live_target(args)
    try:
        result = dynamic.trace_changes(pid, dynamic.reparse(pid, args.va), int(args.size),
                                       samples=int(args.samples), interval=float(args.interval),
                                       limit=int(args.limit))
        print(f"samples={result['samples']} interval={result['interval']}s"
              f" changed_bytes={result['changed_bytes']} in {result['duration']}s")
        for run in result["runs"]:
            print(f"  {run['va']} ({run['size']}B, changed {run['changes']}x, flips {run['flips']})")
            for reading in run["interpretations"]:
                print(f"    as {reading['type']:<7} {reading['first']!r} -> {reading['last']!r}")
            if run.get("monotonic"):
                print(f"    {run['monotonic']}")
    finally:
        backend.close()
    return 0


def cmd_strings_live(args: argparse.Namespace) -> int:
    """Search live memory for strings the target built at run time."""
    backend, dynamic, pid = _live_target(args)
    try:
        result = dynamic.scan_strings(pid, args.needle, min_length=int(args.min_length),
                                      limit=int(args.limit), encoding=args.encoding,
                                      region_filter=args.region or None)
        print(f"{result['count']} match(es) over {result['scanned_bytes']} bytes"
              f" ({result['encoding']})")
        for row in result["matches"]:
            where = f"  [{row['module']}]" if row.get("module") else ""
            print(f"  {row['va']}  {row['encoding']:<5} {row['text']!r}{where}")
    finally:
        backend.close()
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Dump a live module (or a loaded image) to a PE file another tool can open."""
    backend, dynamic, pid = _live_target(args)
    try:
        info = dynamic.resolve_module(pid, args.module)
        data = backend.read(pid, info.base, info.size)
        static = StaticEngine()
        image = static.load_capture("export", data, info.base, path=info.path)
        result = image.save(args.path, raw=args.raw)
        print(f"module   : {info.name}  base={hex(info.base)} size={info.size:#x}")
        print(f"written  : {result['path']}  ({result['size']} bytes, {result['layout']} layout)")
        print(f"sections : {', '.join(result['sections'])}")
        print(f"entry    : {result['entry_rva']} (RVA)")
        if not args.raw:
            print("note     : demapped, so IDA/Ghidra and pefile will open it")
    finally:
        backend.close()
    return 0


def cmd_merge(args: argparse.Namespace) -> int:
    """Merge a function's field accesses with live values — the usable struct."""
    backend, dynamic, pid = _live_target(args)
    try:
        static = StaticEngine()
        static.load_file(args.path, key="merge")
        inferred = dynamic.infer_struct(pid, dynamic.reparse(pid, args.va), int(args.size),
                                        stride=int(args.stride) or None,
                                        count=int(args.count), align=int(args.align))
        merged = static.merge_layout("merge", parse_address(args.function), inferred)
        for layout in merged:
            print(layout["c_struct"])
            for group in layout["vectors"]:
                print(f"  // {group['suggestion']}   ({group['kind']} at {group['offset']})")
            summary = layout["summary"]
            print(f"  fields={summary['fields']} confirmed={summary['confirmed_both']}"
                  f" code_only={summary['code_only']} data_only={summary['data_only']}")
            if layout["code_only_offsets"]:
                print(f"  code only : {', '.join(layout['code_only_offsets'])}")
            if layout["data_only_offsets"]:
                print(f"  data only : {', '.join(layout['data_only_offsets'])}")
            for note in layout["notes"]:
                print(f"  note: {note}")
            print()
    finally:
        backend.close()
    return 0


def cmd_mcp(_args: argparse.Namespace) -> int:
    from .mcp_server import main as mcp_main

    mcp_main()
    return 0


def cmd_demo(_args: argparse.Namespace) -> int:
    """Exercise both engines against the deterministic mock target."""
    backend = create_backend("mock", name="demo")
    backend.open()
    dynamic = DynamicEngine(backend)
    static = StaticEngine()
    print(f"phantomscope {__version__}  (mock backend, no hardware needed)\n")

    processes = dynamic.list_processes()
    pid = processes[0]["pid"]
    print(f"process  : {processes[0]['name']} (pid {pid})")
    modules = dynamic.list_modules(pid)
    print(f"modules  : {[m['name'] for m in modules]}")
    threads = dynamic.threads(pid)
    print(f"threads  : {[hex(t['tid']) for t in threads]}")
    print(f"callstack: {dynamic.callstack(pid, threads[0]['tid'])}")

    heap = 0x21A_0000_0000
    print(f"\nhealth   : {dynamic.read_typed(pid, heap + 0x120, 'int32')}")
    scan = dynamic.scan_value(pid, 100, "int32", label="health")
    print(f"scan     : {scan['count']} hits for 100 -> {scan['addresses'][:4]}")
    dynamic.write(pid, heap + 0x120, value=250, value_type="int32", note="demo patch")
    print(f"patched  : {dynamic.read_typed(pid, heap + 0x120, 'int32')}")
    print(f"restore  : {dynamic.restore_all()} -> "
          f"{dynamic.read_typed(pid, heap + 0x120, 'int32')}")

    # Structure recovery: a pointer path, a container, and an inferred layout.
    chain = dynamic.resolve_pointer_chain(pid, heap + 0x1E0, [0, 8], value_type="uint32")
    print(f"\nchain    : {chain['base']} + {chain['offsets']} -> {chain['address']}"
          f" = {chain['value']}")
    container = dynamic.expand_container(pid, heap + 0x180, fields="0x0:int32,0x8:char[8]")
    print(f"container: {container['primary']['kind']}"
          f" element={container['element_size']}"
          f" ({container['primary']['element_size_source']})"
          f" count={container['element_count']}")
    for element in container["elements"]:
        values = {f["offset"]: f.get("value") for f in element.get("fields", [])}
        print(f"  {element['va']}  id={values.get('0x0')} name={values.get('0x8')}")
    inferred = dynamic.infer_struct(pid, 0x21B_0000_0000, 0x20, stride=0x20, count=4, align=4)
    print(f"inferred : {len(inferred['fields'])} field(s),"
          f" strings {[s['text'] for s in inferred['strings']]}")
    watched = dynamic.trace_value(pid, heap + 0x120, "int32", samples=3, interval=0.01)
    print(f"trace    : {'constant' if watched['constant'] else 'changing'}"
          f" values={[row['value'] for row in watched['series']]}")

    module_row = modules[0]
    static.load_capture("demo", backend.read(pid, module_row["base"], module_row["size"]),
                        module_row["base"], path=module_row["name"])
    print(f"\nstatic   : {static.summary('demo')['arch']} module captured through the backend")
    for insn in static.disassemble("demo", None, count=5):
        print(f"  {insn['va']:#x}  {insn['text']}")

    print(f"emulation: {'available' if emulator_available() else 'not installed'}")
    if emulator_available():
        image = static.get("demo")
        emu = emulator_for(image)
        result = emu.run_until(image.base + 0x1015, max_steps=64)
        print(f"  emu run : {result['from']} -> {result['to']} ({result['reason']})")

    image = static.get("demo")
    triage = static.packing_report("demo")
    print(f"\ntriage   : packing score {triage['score']}/10 ({triage['verdict']}), "
          f"{triage['functions']} function(s), {triage['imports']} import(s)")
    lifted = static.decompile("demo", image.base + 0x1015)
    print(f"decompile: {lifted['signature']}  [{lifted['confidence']}]")
    for line in lifted["text"].splitlines()[2:]:
        print(f"  {line}")
    print(f"immediates: {static.search_immediates('demo', 5)['counts']} hit(s) for 0x5")
    backend.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phantomscope",
        description="DMA reverse-engineering toolkit (static + dynamic) with an MCP server",
    )
    parser.add_argument("--version", action="version", version=f"phantomscope {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("mcp", help="run the MCP server on stdio")
    p.set_defaults(func=cmd_mcp)

    p = sub.add_parser("demo", help="exercise every capability on the mock target")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("static", help="PE summary")
    p.add_argument("path")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_static)

    p = sub.add_parser("functions", help="list discovered functions")
    p.add_argument("path")
    p.add_argument("--limit", type=int, default=200)
    p.set_defaults(func=cmd_functions)

    p = sub.add_parser("disasm", help="disassemble an address or function")
    p.add_argument("path")
    p.add_argument("va", nargs="?", default="")
    p.add_argument("--count", type=int, default=40)
    p.add_argument("--function", action="store_true")
    p.set_defaults(func=cmd_disasm)

    p = sub.add_parser("strings", help="extract strings")
    p.add_argument("path")
    p.add_argument("--contains", default="")
    p.add_argument("--limit", type=int, default=2000)
    p.set_defaults(func=cmd_strings)

    p = sub.add_parser("scan", help="AOB scan an image")
    p.add_argument("path")
    p.add_argument("pattern")
    p.add_argument("--limit", type=int, default=200)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("decompile", help="pseudo-C for one function or all of them")
    p.add_argument("path")
    p.add_argument("va", nargs="?", default="")
    p.add_argument("--limit", type=int, default=20, help="functions to render when va is omitted")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_decompile)

    p = sub.add_parser("apis", help="imported APIs and their call sites")
    p.add_argument("path")
    p.add_argument("--needle", default="", help="filter by API name")
    p.set_defaults(func=cmd_apis)

    p = sub.add_parser("triage", help="packing score and crypto constants")
    p.add_argument("path")
    p.set_defaults(func=cmd_triage)

    p = sub.add_parser("immediates", help="where a constant is used")
    p.add_argument("path")
    p.add_argument("value")
    p.add_argument("--width", type=int, default=4, choices=[4, 8])
    p.add_argument("--limit", type=int, default=200)
    p.set_defaults(func=cmd_immediates)

    p = sub.add_parser("diff", help="structural diff of two builds")
    p.add_argument("left")
    p.add_argument("right")
    p.add_argument("--min-similarity", dest="min_similarity", type=float, default=0.6)
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser(
        "physical", help="inspect a raw physical dump (no OS assumptions)"
    )
    p.add_argument("path")
    p.add_argument("--memmap", default="", help="pa,size;pa,size memory map")
    p.add_argument("--cr3", default="", help="CR3 used for virtual reads")
    p.add_argument("--capture", default="", help="capture the PE at this physical address")
    p.add_argument("--base", default="", help="override the load base of the capture")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--count", type=int, default=8)
    p.set_defaults(func=cmd_physical)

    # -- live target commands -------------------------------------------------
    # Every one of these takes the same target selector; they differ only in the
    # question they ask about the memory they find.
    def live(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
        parser.add_argument("--process", default="", help="image name substring")
        parser.add_argument("--pid", type=int, default=0)
        parser.add_argument("--kind", default="memprocfs",
                            choices=["memprocfs", "physical", "mock", "game"])
        parser.add_argument("--device", default="fpga", help="fpga, dump path or mock")
        return parser

    p = live(sub.add_parser("chain", help="resolve a pointer path in a live process"))
    p.add_argument("base", help="module+0x10 or an address")
    p.add_argument("offsets", nargs="?", default="", help='comma separated, e.g. "0x10,0x38,0x8"')
    p.add_argument("--value-type", dest="value_type", default="")
    p.add_argument("--read-size", dest="read_size", type=parse_address, default=0)
    p.set_defaults(func=cmd_chain)

    p = live(sub.add_parser("object", help="dump one live object"))
    p.add_argument("va")
    p.add_argument("--size", type=parse_address, default=0x80)
    p.add_argument("--fields", default="", help='"0x0:int32,0x8:pointer"')
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_object)

    p = live(sub.add_parser("array", help="read a live array"))
    p.add_argument("base")
    p.add_argument("--stride", type=parse_address, required=True)
    p.add_argument("--count", type=parse_address, required=True)
    p.add_argument("--fields", default="")
    p.add_argument("--follow", action="store_true", help="treat the array as pointers")
    p.add_argument("--object-size", dest="object_size", type=parse_address, default=0x40)
    p.add_argument("--limit", type=parse_address, default=128)
    p.set_defaults(func=cmd_array)

    p = live(sub.add_parser("infer", help="infer a live structure layout"))
    p.add_argument("va")
    p.add_argument("--size", type=parse_address, default=0x40)
    p.add_argument("--count", type=parse_address, default=1)
    p.add_argument("--stride", type=parse_address, default=0)
    p.add_argument("--align", type=int, default=8, choices=[1, 2, 4, 8])
    p.set_defaults(func=cmd_infer)

    p = live(sub.add_parser("container", help="detect a vector/TArray/string in memory"))
    p.add_argument("va")
    p.add_argument("--element-size", dest="element_size", type=parse_address, default=0)
    p.add_argument("--expand", action="store_true", help="list the elements")
    p.add_argument("--fields", default="")
    p.add_argument("--limit", type=parse_address, default=64)
    p.set_defaults(func=cmd_container)

    p = live(sub.add_parser("trace", help="poll a range and report what changed"))
    p.add_argument("va")
    p.add_argument("size", type=parse_address)
    p.add_argument("--samples", type=parse_address, default=8)
    p.add_argument("--interval", type=float, default=0.02)
    p.add_argument("--limit", type=parse_address, default=64)
    p.set_defaults(func=cmd_trace)

    p = live(sub.add_parser("memstrings", help="find strings in live memory"))
    p.add_argument("needle", nargs="?", default="")
    p.add_argument("--min-length", dest="min_length", type=parse_address, default=6)
    p.add_argument("--encoding", default="both", choices=["ascii", "utf16", "both"])
    p.add_argument("--region", default="", help="module name or region tag substring")
    p.add_argument("--limit", type=parse_address, default=500)
    p.set_defaults(func=cmd_strings_live)

    p = live(sub.add_parser("dumpmodule", help="dump a live module to a loadable PE"))
    p.add_argument("module")
    p.add_argument("path")
    p.add_argument("--raw", action="store_true", help="keep the RVA layout")
    p.set_defaults(func=cmd_export)

    p = live(sub.add_parser(
        "merge", help="merge a function's field accesses with live values"))
    p.add_argument("path", help="PE the function lives in")
    p.add_argument("function", help="any address inside the function")
    p.add_argument("va", help="a live instance of the object")
    p.add_argument("--size", type=parse_address, default=0x40)
    p.add_argument("--stride", type=parse_address, default=0)
    p.add_argument("--count", type=parse_address, default=8)
    p.add_argument("--align", type=int, default=4, choices=[1, 2, 4, 8])
    p.set_defaults(func=cmd_merge)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except PhantomError as exc:
        print(json.dumps(exc.to_dict(), indent=2), file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
