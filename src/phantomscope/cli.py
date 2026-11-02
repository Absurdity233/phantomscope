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
