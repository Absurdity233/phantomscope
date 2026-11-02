"""Live-backend probe: open the configured device and report what works.

Run against the FPGA (default), a dump, or pmem::

    .venv\\Scripts\\python.exe tools\\probe_backend.py fpga
    .venv\\Scripts\\python.exe tools\\probe_backend.py C:\\dumps\\win10.raw

Every step is timed and failures are reported, so this doubles as the
hardware sanity check before trusting a session.
"""

from __future__ import annotations

import argparse
import sys
import time
import traceback


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("device", nargs="?", default="fpga")
    parser.add_argument("--process", default="", help="attach to this process name/PID")
    parser.add_argument("--options", default="", help="extra MemProcFS arguments")
    args = parser.parse_args()

    from phantomscope.backends.memprocfs_backend import MemProcFsBackend

    backend = MemProcFsBackend(device=args.device, options=args.options.split(), name="probe")
    started = time.time()
    try:
        backend.open()
    except Exception as exc:
        print(f"open failed after {time.time() - started:.1f}s: {exc}")
        if getattr(exc, "detail", None):
            print(f"hint: {exc.detail}")
        return 1
    print(f"opened in {time.time() - started:.1f}s (bits={backend.bits})")

    def timed(label, func, *a, **kw):
        start = time.time()
        try:
            value = func(*a, **kw)
        except Exception as exc:  # noqa: BLE001 - probe wants every failure
            print(f"{label:<16} FAILED after {time.time() - start:.1f}s: {exc}")
            traceback.print_exc(limit=2)
            return None
        elapsed = time.time() - start
        extra = ""
        if isinstance(value, list):
            extra = f"{len(value)} items"
        elif isinstance(value, (bytes, bytearray)):
            extra = f"{len(value)} bytes"
        print(f"{label:<16} ok in {elapsed:.1f}s {extra}")
        return value

    processes = timed("processes", backend.list_processes)
    if not processes:
        print("no processes; device opened but the target is not readable")
        backend.close()
        return 1

    wanted = args.process
    target = None
    if wanted:
        ident = int(wanted) if wanted.isdigit() else wanted
        target = backend.find_process(ident)
    if target is None:
        target = next((p for p in processes if (p.name or "").lower().endswith(".exe")), processes[0])
    print(f"target           {target.pid} {target.name} {target.path or ''}")

    modules = timed("modules", backend.list_modules, target.pid) or []
    regions = timed("regions", backend.list_regions, target.pid) or []
    threads = timed("threads", backend.list_threads, target.pid) or []
    if threads:
        timed("callstack", backend.thread_callstack, target.pid, threads[0].tid)
    if modules:
        module = modules[0]
        data = timed("read module", backend.read, target.pid, module.base, min(module.size, 0x1000))
        if data:
            print(f"                 MZ header: {data[:2] == b'MZ'}")
        timed("symbolize", backend.symbolize, target.pid, module.base + 0x1000)
    timed("kernel modules", backend.kernel_modules)
    timed("physical map", backend.physical_map)
    timed("handles", backend.list_handles, target.pid)
    backend.close()
    print("closed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
