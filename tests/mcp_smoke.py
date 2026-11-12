"""End-to-end MCP smoke test: spawn the server over stdio and call real tools."""

from __future__ import annotations

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON = os.path.join(ROOT, ".venv", "Scripts", "python.exe")


async def main() -> int:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "phantomscope.mcp_server"],
        env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src")},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print(f"{len(tools.tools)} tools exposed")

            async def call(name: str, **arguments):
                result = await session.call_tool(name, arguments)
                return json.loads(result.content[0].text)

            opened = await call("session_open", device="mock", backend="mock")
            print("session_open:", opened["kind"], opened["processes"], "processes")

            attached = await call("attach", process="demo_target")
            print("attach:", attached["attached"]["pid"])

            read = await call("read_typed", va=hex(0x21A_0000_0120), value_type="int32")
            print("read_typed:", read["value"])

            hits = await call("scan_value", value="100", value_type="int32", label="hp")
            print("scan_value:", hits["count"], "hits")

            captured = await call("capture_module", module="demo_target.exe", key="demo")
            print("capture_module:", captured["summary"]["arch"], captured["summary"]["image_size"])

            static = await call("disassemble", key="demo", count=4)
            print("disassemble:", " | ".join(item["text"] for item in static))

            emu = await call("emu_create", key="demo")
            print("emu_create:", emu["entry"])

            # The dynamic-analysis surface, over a real stdio round trip.
            chain = await call("resolve_pointer_chain", base=hex(0x21A_0000_01E0),
                               offsets="0,8", value_type="uint32")
            print("chain:", chain["address"], "=", chain["value"])

            vector = await call("expand_container", va=hex(0x21A_0000_0180),
                                fields="0x0:int32,0x8:char[8]")
            print("container:", vector["primary"]["kind"],
                  vector["primary"]["element_size"], "x", vector["element_count"])

            series = await call("trace_value", va=hex(0x21A_0000_0120),
                                value_type="int32", samples=2, interval=0.0)
            print("trace_value:", "constant" if series["constant"] else "changing")

            await call("session_close")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
