#!/usr/bin/env python
"""End-to-end MCP smoke test: start the server over stdio and call tools."""

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
        command=PYTHON,
        args=["-m", "phantomscope.mcp_server"],
        env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "src")},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print(f"{len(tools.tools)} tools exposed")
            names = {tool.name for tool in tools.tools}
            assert "session_open" in names and "emu_create" in names

            result = await session.call_tool("session_open", {"device": "mock", "backend": "mock"})
            payload = json.loads(result.content[0].text)
            print("session_open ->", payload["kind"], payload["processes"], "processes")

            result = await session.call_tool("attach", {"process": "demo_target"})
            print("attach ->", json.loads(result.content[0].text)["attached"]["pid"])

            result = await session.call_tool(
                "read_typed", {"va": "0x21a00000120", "value_type": "int32"}
            )
            print("read_typed ->", json.loads(result.content[0].text)["value"])

            result = await session.call_tool("capture_module", {"module": "demo_target.exe", "key": "live"})
            print("capture_module ->", json.loads(result.content[0].text)["summary"]["arch"])

            result = await session.call_tool("disassemble", {"key": "live", "count": 4})
            instructions = json.loads(result.content[0].text)
            print("disassemble ->", " | ".join(item["text"] for item in instructions))

            result = await session.call_tool("session_close", {})
            print("session_close ->", json.loads(result.content[0].text))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
