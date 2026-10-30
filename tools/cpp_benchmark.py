"""Compare two native builds on identical executed guest work.

Example (run without concurrent test jobs):
  python tools/cpp_benchmark.py --baseline old/alicore.dll --candidate cpp/build/alicore.dll \
      --output report/benchmark.json

Fresh worker processes alternate build order in randomized pairs. Setup, state
hashing and teardown are outside the timed region. All instruction skipping and
firmware HLE are disabled. State equality is required before reporting timings.
CPU time is the primary measure; wall time is also retained to expose host load.
These workloads measure specific mechanisms and early boot, not all firmware.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
CASES = ("alu", "ram", "count", "count_fractional", "count_timer",
         "device_plain", "mmio_python", "firmware")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pin_cpu(cpu):
    """Keep paired workers on the same logical CPU, including hybrid Windows hosts."""
    if os.name == "nt":
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.SetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        if cpu >= ctypes.sizeof(ctypes.c_size_t) * 8:
            raise ValueError("CPU index exceeds the current Windows processor group")
        if not kernel.SetProcessAffinityMask(kernel.GetCurrentProcess(), 1 << cpu):
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        os.sched_setaffinity(0, {cpu})


def core_state(core, cc):
    from unicorn.mips_const import UC_MIPS_REG_FCSR
    return {
        "gpr": [core.reg_read(2 + i) for i in range(32)],
        "pc": core.reg_read(1), "hi": core.reg_read(129), "lo": core.reg_read(130),
        "fpr": [core.reg_read(cc.REG_F0 + i) for i in range(32)],
        "fcsr": core.reg_read(UC_MIPS_REG_FCSR),
        "cp0": [core.reg_read(cc.REG_CP0_BASE + i) for i in range(256)],
        "fields": {name: core.get(getattr(cc, name)) for name in (
            "F_ICOUNT", "F_EXECUTED", "F_COUNT", "F_STATUS", "F_CAUSE_VALUE", "F_EPC",
            "F_COMPARE", "F_TIMER_IRQS", "F_IC_IRQS", "F_UART_IRQS", "F_IC_LINES",
            "F_UART_IP3", "F_UART_PENDING", "F_UART_DELIVERED", "F_DS_ACTIVE", "F_DS_TARGET",
            "F_DS_M16", "F_M16", "F_LLBIT", "F_BADVADDR", "F_CNUM", "F_CDEN")},
    }


def worker(case, scale, firmware_instructions):
    import ctypes
    import struct
    sys.path.insert(0, str(ROOT / "src"))
    import cpp_core as cc
    fields = {name: getattr(cc, name) for name in (
        "F_ICOUNT", "F_EXECUTED", "F_BLOCK_RUNS", "F_BLOCK_BUILDS",
        "F_IDLE_SKIPPED", "F_SPIN_SKIPPED", "F_POLL_SKIPPED", "F_FF_SKIPPED")}
    callbacks = [0, 0]
    mmio_value = [0]
    buf = None
    sim = None
    uart = []
    if case == "firmware":
        from simulator import AliMipsSimulator, resolve_dump, flash_size_for
        firmware = resolve_dump("dump_maciej.bin")
        sim = AliMipsSimulator(engine="cpp", rom_size=flash_size_for(firmware),
                               ram_size=128 * 1024 * 1024, log_handler=lambda _: None)
        for name in ("lzma_hle", "delay_hle", "idle_skip", "poll_skip", "skip_irq_disable"):
            setattr(sim, name, False)
        sim.hook_every_instruction = False
        sim.calibration_slices = 10**12
        sim.exact_count_threshold = 10**12
        sim.setSPIDump(False)
        sim.setUartHandler(uart.append)
        sim.loadFile(firmware)
        core = sim._core
        core.set(cc.F_IDLE_SKIP, 0)
        core.set(cc.F_SPIN_SKIP, 0)
        # Retain this simulator's modeled MMIO latency, identically in both builds.
        run = lambda: sim.run(max_instructions=firmware_instructions)
    else:
        core = cc.CppUc()
        core.mem_map(0, 0x10000)
        for field, value in ((cc.F_EXACT, 1), (cc.F_IDLE_SKIP, 0), (cc.F_SPIN_SKIP, 0),
                             (cc.F_HOST_ACCESS_COST, 0), (cc.F_BLOCKS_ON, 1)):
            core.set(field, value)
        if case == "alu":
            code = [0x25080001, 0x01284821, 0x01495026, 0x000A58C0, 0, 0x150CFFFA, 0]
            iterations = 10_000_000 * scale
        elif case.startswith("count"):
            code = [0x40084800, 0x01284821, 0x254A0001, 0, 0x154CFFFB, 0]
            iterations = 12_000_000 * scale
            if case == "count_fractional":
                core._lib.ali_set_count_ratio(core.handle, 3, 2)
            elif case == "count_timer":
                core.set(cc.F_COMPARE_WRITE, 0x7FFFFFFF)
        else:
            code = [0x8E080000, 0x25080001, 0xAE080000, 0x25290001, 0x152CFFFB, 0]
            iterations = (12_000_000 if case == "ram" else
                          8_000_000 if case == "device_plain" else 500_000) * scale
            core.reg_write(2 + 16, 0x80002000 if case == "ram" else 0xB8001000)
            if case == "device_plain":
                buf = ctypes.create_string_buffer(0x2000)
                core._lib.ali_set_device_window(core.handle, 0x18000000, buf, len(buf), None, None)
            elif case == "mmio_python":
                def read(_core, offset, size, user):
                    callbacks[0] += 1
                    return mmio_value[0]
                def write(_core, offset, size, value, user):
                    callbacks[1] += 1
                    mmio_value[0] = value
                core.mmio_map(0x18001000, 0x1000, read, None, write, None)
        core.reg_write(2 + 12, 0xFFFFFFFF)
        core.mem_write(0x1000, struct.pack(f"<{len(code)}I", *code))
        core.emu_start(0x80001000, 0xFFFFFFFF, count=100 * len(code))
        instructions = iterations * len(code)
        run = lambda: core.emu_start(0x80001000, 0xFFFFFFFF, count=instructions)
    before = {name: core.get(field) for name, field in fields.items()}
    callback_before = callbacks.copy()
    cpu_start = time.process_time()
    wall_start = time.perf_counter()
    run()
    wall_seconds = time.perf_counter() - wall_start
    cpu_seconds = time.process_time() - cpu_start
    counters = {name: core.get(field) - before[name] for name, field in fields.items()}
    assert all(counters[name] == 0 for name in fields if name.endswith("SKIPPED")), counters
    if sim is None:
        assert counters["F_EXECUTED"] == counters["F_ICOUNT"] == instructions, counters
        iteration_register = 8 if case == "alu" else 10 if case.startswith("count") else 9
        assert core.reg_read(2 + iteration_register) == iterations + 100
        if case == "mmio_python":
            assert [v - b for v, b in zip(callbacks, callback_before)] == [iterations] * 2
    else:
        assert counters["F_EXECUTED"] == firmware_instructions, counters
        assert not any((sim.idle_skipped, sim.poll_skipped, sim.delay_calls, sim.lzma_decodes))
    state = core_state(core, cc)
    state["ram_sha256"] = digest(core.mem_read(0, sim.ram_size if sim else 0x10000))
    if sim:
        state["device_sha256"] = digest(sim._mmio_view)
        state["uart"] = "".join(uart)
        state["firmware_sha256"] = digest(Path(firmware).read_bytes())
    else:
        state.update(device_sha256=digest(buf.raw) if buf else None,
                     callback_counts=callbacks, mmio_value=mmio_value[0])
    return {"case": case, "wall_seconds": wall_seconds, "cpu_seconds": cpu_seconds,
            "dll_sha256": digest(Path(cc.DLL_PATH).read_bytes()), "state": state,
            "host_access_cost": core.get(cc.F_HOST_ACCESS_COST), "counters": counters}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--scale", type=int, default=1)
    parser.add_argument("--cpu", type=int, help="pin each worker to this logical CPU to reduce migration noise")
    parser.add_argument("--firmware-instructions", type=int, default=60_000_000)
    parser.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    parser.add_argument("--worker", choices=CASES, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if min(args.repeats, args.scale, args.firmware_instructions) < 1:
        parser.error("repeat, scale and instruction counts must be positive")
    if args.cpu is not None and args.cpu < 0:
        parser.error("CPU index must not be negative")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.worker:
        if args.cpu is not None:
            pin_cpu(args.cpu)
        result = worker(args.worker, args.scale, args.firmware_instructions)
        result["cpu_affinity"] = args.cpu
        args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return
    if not args.baseline or not args.candidate:
        parser.error("--baseline and --candidate are required")
    variants = {"baseline": args.baseline.resolve(), "candidate": args.candidate.resolve()}
    rng = random.Random(20261028)
    pairs = [(case, repeat) for repeat in range(args.repeats) for case in args.cases]
    rng.shuffle(pairs)
    rows = []
    reference = {}
    raw_dir = args.output.with_suffix("")
    raw_dir.mkdir(parents=True, exist_ok=True)
    for case, repeat in pairs:
        order = list(variants)
        rng.shuffle(order)
        for variant in order:
            row_path = raw_dir / f"{case}-{repeat}-{variant}.json"
            env = dict(os.environ, ALISIM_CPP_DLL=str(variants[variant]))
            cmd = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", case,
                   "--scale", str(args.scale), "--firmware-instructions", str(args.firmware_instructions),
                   "--output", str(row_path)]
            if args.cpu is not None:
                cmd.extend(("--cpu", str(args.cpu)))
            subprocess.run(cmd, cwd=ROOT, env=env, check=True)
            row = json.loads(row_path.read_text(encoding="utf-8"))
            row.update(variant=variant, repeat=repeat)
            if case in reference:
                assert row["state"] == reference[case], f"Guest-state mismatch: {row_path}"
            else:
                reference[case] = row["state"]
            rows.append(row)
            print(f"{case:13} {repeat} {variant:9} CPU {row['cpu_seconds']:.4f}s wall {row['wall_seconds']:.4f}s", flush=True)
    summary = []
    for case in args.cases:
        item = {"case": case}
        for metric in ("cpu_seconds", "wall_seconds"):
            samples = {variant: [r[metric] for r in rows if r["case"] == case and r["variant"] == variant]
                       for variant in variants}
            for variant in variants:
                item[f"{variant}_median_{metric}"] = statistics.median(samples[variant])
            paired_ratios = []
            for repeat in range(args.repeats):
                pair = {r["variant"]: r[metric] for r in rows if r["case"] == case and r["repeat"] == repeat}
                paired_ratios.append(pair["baseline"] / pair["candidate"])
            item[f"paired_{metric}_speedups"] = paired_ratios
            item[f"median_paired_{metric}_speedup"] = statistics.median(paired_ratios)
        summary.append(item)
    report = {"python": sys.version, "variants": {k: str(v) for k, v in variants.items()},
              "repeats": args.repeats, "cpu_affinity": args.cpu,
              "state_validation": "All guest-state snapshots identical per workload; all skips/HLE disabled.",
              "limitations": "Snapshots cover recorded CPU registers/fields, RAM, device-buffer bytes and UART, not all hidden device state. Pinning does not isolate SMT siblings or CPU-frequency changes. Firmware retains modeled MMIO latency. Workload speedups are not a whole-simulator speedup.",
              "summary": summary, "runs": rows}
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
