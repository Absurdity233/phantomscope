"""Image triage: packing/virtualisation hints, crypto constants, immediates.

Before reverse engineering a function you want to know what kind of binary you are
holding, and while inside a function you want to know whether a magic number is
a hash constant or a licence check.  Both questions are cheap to answer from the
mapped image and are answered here:

* :func:`packing_report` — entropy, section anomalies, import count, whether the
  analyser actually recovered code, TLS callbacks, overlay.  It returns *evidence
  and a score*, not a verdict handed down from nowhere.
* :func:`crypto_constants` — known tables and round constants (AES S-box, CRC-32
  table, MD5/SHA IVs, FNV/xxHash primes, base64 alphabet) located by value.
* :func:`search_immediates` — "where is this number used", in code and in data,
  which is how you find the comparison behind an HP check or a magic header.

Everything is heuristic and says so: a hit means "the bytes are here", not "this
is definitely AES".
"""

from __future__ import annotations

from .index import CodeIndex
from .pe import PEImage, entropy
from .scan import scan_bytes

#: (name, needle bytes, description) — needles are the literal stored form.
_CRYPTO_PATTERNS: list[tuple[str, str, bytes, str]] = [
    ("aes_sbox", "table", bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"),
     "AES/SubBytes S-box (first 16 bytes)"),
    ("aes_inv_sbox", "table", bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"),
     "inverse AES S-box (unusual outside white-box crypto)"),
    ("crc32_table", "table", bytes.fromhex("00000000963007772c610eeeba510999"),
     "CRC-32 (poly 0xEDB88320) lookup table"),
    ("sha256_iv", "constant", bytes.fromhex("67e6096a85ae67bb"),
     "SHA-256 initial hash values"),
    ("sha256_k", "constant", bytes.fromhex("982f8a42"), "SHA-256 round constant 0x428a2f98"),
    ("md5_iv", "constant", bytes.fromhex("0123456789abcdef"), "MD5/SHA-1 initial state 0x67452301,0xefcdab89"),
    ("md5_k", "constant", bytes.fromhex("78a46ad7"), "MD5 round constant 0xd76aa478"),
    ("tea_delta", "constant", bytes.fromhex("b979379e"), "TEA/XTEA delta 0x9e3779b9"),
    ("xxhash32_prime", "constant", bytes.fromhex("b179379e"), "xxHash32 prime 0x9e3779b1"),
    ("xxhash64_prime", "constant", bytes.fromhex("87caeb85b179379e"), "xxHash64 prime 0x9e3779b185ebca87"),
    ("fnv1a_64", "constant", bytes.fromhex("25238248e49cf2cb"), "FNV-1a 64-bit offset basis"),
    ("fnv1a_32", "constant", bytes.fromhex("c59d1c81"), "FNV-1a 32-bit offset basis"),
    ("murmur3_c1", "constant", bytes.fromhex("6bcaeb85"), "MurmurHash3 constant 0x85ebca6b"),
    ("base64_alphabet", "table",
     b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
     "base64 alphabet (encode/decode routine or a key table)"),
    ("hex_alphabet", "table", b"0123456789abcdefABCDEF", "hex digit table"),
]

_CRYPTO_LIMIT_PER_SECTION = 16


def packing_report(index: CodeIndex) -> dict:
    """Evidence for and against packing / virtualisation, with a 0-10 score."""
    image = index.image
    findings: list[dict] = []
    score = 0

    def add(label: str, weight: int, detail: str, va: int | None = None) -> None:
        nonlocal score
        score += weight
        entry = {"finding": label, "weight": weight, "detail": detail}
        if va is not None:
            entry["va"] = hex(va)
        findings.append(entry)

    executable = [section for section in image.sections if section.executable and section.vsize]
    writable = [section for section in image.sections if section.writable]

    for section in image.sections:
        value = section.entropy if section.entropy is not None else entropy(
            image.read(section.va, min(section.vsize, 0x100000))
        )
        if section.executable and value >= 7.2:
            add("high_entropy_code", 3,
                f"{section.name} entropy {value} — packed or encrypted code", section.va)
        elif value >= 7.5:
            add("high_entropy_data", 1,
                f"{section.name} entropy {value} — compressed or encrypted data", section.va)

    for section in image.sections:
        if section.executable and section.writable:
            add("writable_code", 3,
                f"{section.name} is writable and executable (self-modifying code)", section.va)
        if section.vsize and not section.raw_size:
            add("virtual_only_section", 3,
                f"{section.name} has no file data: filled in at runtime", section.va)

    interesting = {".text", ".data", ".rdata", ".pdata", ".idata", ".rsrc", ".reloc", ".bss",
                   ".tls", ".didat", ".edata", ".CRT", ".gfids", ".00cfg"}
    odd = [section.name for section in image.sections if section.name not in interesting]
    if len(odd) >= 2:
        add("nonstandard_sections", 1, "sections renamed or packer-added: " + ", ".join(odd))

    imports = image.imports
    if not imports:
        add("no_imports", 3, "no import table — APIs are resolved by hash or manually")
    elif len(imports) < 8:
        add("few_imports", 1, f"only {len(imports)} imported functions")

    code_bytes = sum(section.vsize for section in executable)
    functions = len(index.function_starts)
    if code_bytes and functions:
        per_kb = functions / max(1, code_bytes / 1024)
        if per_kb < 0.15:
            add("little_code_recovered", 2,
                f"{functions} function(s) in {code_bytes // 1024} KiB of code "
                f"({per_kb:.2f}/KiB) — packed, virtualised or a jump-table blob")

    callbacks = image.tls_callbacks()
    if callbacks:
        add("tls_callbacks", 2, f"{len(callbacks)} TLS callback(s) run before the entry point")

    entry_section = image.section_for_va(image.entry)
    if entry_section is not None and entry_section.writable:
        add("entry_in_writable_section", 3,
            f"entry point lives in writable section {entry_section.name}")
    if executable and entry_section is not None and entry_section is not executable[0]:
        add("entry_not_in_first_code_section", 1,
            f"entry point is in {entry_section.name}, not {executable[0].name}")

    flags = image.summary().get("security_flags") or []
    if not flags:
        add("no_mitigations", 1, "no ASLR/NX/CFG flags in DllCharacteristics")

    overlay = image.overlay_size()
    if overlay and overlay > 0x400:
        add("overlay", 1, f"{overlay} bytes of data past the last section")

    return {
        "image": image.path,
        "score": min(score, 10),
        "verdict": ("likely packed or virtualised" if score >= 6 else
                    "some anomalies" if score >= 3 else "not obviously packed"),
        "entropy": {section.name: section.entropy for section in image.sections},
        "imports": len(imports),
        "import_modules": len({imp.module for imp in imports}),
        "functions": functions,
        "code_kib": code_bytes // 1024,
        "findings": findings,
    }


def crypto_constants(index: CodeIndex, *, limit: int = 40) -> list[dict]:
    """Locate well-known crypto/hash tables and round constants by value.

    One pass per section (not per pattern): a 26 MB image has 26 MB of bytes to
    search, and copying it once per pattern made triage slow for no reason.
    """
    image = index.image
    hits: list[dict] = []
    for section in image.sections:
        data = image.read(section.va, section.vsize)
        if not data:
            continue
        for name, kind, needle, description in _CRYPTO_PATTERNS:
            found = 0
            for offset in scan_bytes(data, needle, limit=_CRYPTO_LIMIT_PER_SECTION):
                hits.append({
                    "name": name,
                    "kind": kind,
                    "section": section.name,
                    "va": hex(section.va + offset),
                    "description": description,
                })
                found += 1
                if len(hits) >= limit:
                    break
            if len(hits) >= limit:
                break
        if len(hits) >= limit:
            break
    hits.sort(key=lambda item: (int(item["va"], 16), item["name"]))
    return hits


def search_immediates(index: CodeIndex, value: int, *, width: int = 4,
                      limit: int = 200, include_code_bytes: bool = False) -> dict:
    """Every place ``value`` appears: as an instruction immediate and as data.

    ``width`` 4 or 8 picks how the value is stored; for code both the plain and
    the sign-extended 32-bit encoding are matched, because ``cmp rax, -1`` encodes
    ``0xFFFFFFFF``.  Executable sections are searched as *code* only unless
    ``include_code_bytes`` is set — matching raw bytes there mostly reports
    instruction encodings back at you.
    """
    if width not in (4, 8):
        width = 4
    image = index.image
    mask = (1 << (width * 8)) - 1
    wanted = value & mask
    alternatives = {wanted}
    if width == 8:
        alternatives.add(value & 0xFFFFFFFF)
        alternatives.add(value & 0xFFFFFFFFFFFFFFFF)
    else:
        alternatives.add(value & 0xFFFFFFFF)

    code: list[dict] = []
    for va, insn in index.insns.items():
        decoded = index.disassembler.one(image.read(va, 16), va)
        if decoded is None:
            continue
        for operand in decoded.operands:
            if operand.type != 2:  # X86_OP_IMM
                continue
            if (int(operand.imm) & mask) in alternatives or int(operand.imm) == value:
                code.append({"va": hex(va), "function": hex(index.function_start(va) or va),
                             "text": insn.text})
                break
        if len(code) >= limit:
            break

    data: list[dict] = []
    needles = {int(candidate).to_bytes(width, "little", signed=False) for candidate in alternatives}
    for section in image.sections:
        if section.executable and not include_code_bytes:
            continue
        blob = image.read(section.va, section.vsize)
        if not blob:
            continue
        for needle in needles:
            for offset in scan_bytes(blob, needle, limit=limit):
                data.append({"va": hex(section.va + offset), "section": section.name,
                             "width": width})
                if len(data) >= limit:
                    break
            if len(data) >= limit:
                break

    return {
        "value": hex(value),
        "width": width,
        "code": code,
        "data": data,
        "counts": {"code": len(code), "data": len(data)},
    }
