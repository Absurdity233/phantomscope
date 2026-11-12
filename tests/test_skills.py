"""Every tool named in a skill must exist, with the arguments it uses.

A skill that calls a renamed or removed tool is worse than no skill: it fails at
the moment someone is following it.  This test reads the markdown and checks the
references against the live MCP registry.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest

from phantomscope import mcp_server as mcp

SKILLS = Path(__file__).resolve().parents[1] / "skills"
CALL = re.compile(r'\{"tool":\s*"([a-z_0-9]+)"(,\s*"arguments":\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\})?')


def _skills() -> list[Path]:
    return sorted(SKILLS.glob("*/SKILL.md"))


def _signatures() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for name, fn in inspect.getmembers(mcp, inspect.isfunction):
        if getattr(fn, "__module__", "") == mcp.__name__:
            out[name] = set(inspect.signature(fn).parameters)
    return out


def test_skills_exist():
    assert len(_skills()) >= 6


@pytest.mark.parametrize("path", _skills(), ids=lambda p: p.parent.name)
def test_frontmatter_matches_the_directory(path):
    text = path.read_text(encoding="utf8")
    assert text.startswith("---"), "frontmatter must be the first thing in the file"
    front = text[3 : text.index("---", 3)]
    name = re.search(r"^name:\s*(\S+)", front, re.M)
    description = re.search(r"^description:\s*(.+)$", front, re.M)
    assert name and description
    assert name.group(1) == path.parent.name
    assert len(description.group(1)) > 40, "a description has to say when to trigger"


@pytest.mark.parametrize("path", _skills(), ids=lambda p: p.parent.name)
def test_every_tool_reference_exists(path):
    signatures = _signatures()
    unknown = {
        tool for tool in CALL.findall(path.read_text(encoding="utf8"))
        for tool in [tool[0]] if tool not in signatures
    }
    assert not unknown, f"{path.parent.name} calls tools that do not exist: {sorted(unknown)}"


@pytest.mark.parametrize("path", _skills(), ids=lambda p: p.parent.name)
def test_every_argument_reference_exists(path):
    signatures = _signatures()
    problems: list[str] = []
    for match in CALL.finditer(path.read_text(encoding="utf8")):
        tool, args = match.group(1), match.group(3) or ""
        if tool not in signatures:
            continue
        for key in re.findall(r'"([a-z_0-9]+)":', args):
            if key not in signatures[tool]:
                problems.append(f"{tool}({key}=)")
    assert not problems, f"{path.parent.name} uses unknown arguments: {sorted(set(problems))}"
