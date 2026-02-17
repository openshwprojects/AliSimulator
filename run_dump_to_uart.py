"""
Run dump.bin until UART output is detected.
Uses run() in batches for speed, with progress reporting and stall detection.
"""
import sys
import time
sys.stdout.reconfigure(line_buffering=True)

from simulator import AliMipsSimulator, ISAMode
from unicorn import *
from unicorn.mips_const import *

# ─── Configuration ───────────────────────────────────────────────────
FIRMWARE = "dump.bin"
MAX_INSTRUCTIONS = 100_000_000      # safety cap
TRACE_AFTER = 667_800               # just before crash at 668099
BATCH_SIZE = 100_000                # instructions per run() batch
STALL_WINDOW = 0                    # disabled - busy-wait loops are expected

# ─── UART capture ────────────────────────────────────────────────────
uart_output = []
uart_chars = 0

def on_uart(char):
    global uart_chars
    uart_chars += 1
    uart_output.append(char)
    sys.stdout.write(char)
    sys.stdout.flush()

# ─── Main ─────────────────────────────────────────────────────────────
def main():
    print(f"=== Run dump.bin to UART ===")
    print(f"Firmware: {FIRMWARE}")
    print(f"Max instructions: {MAX_INSTRUCTIONS:,}")
    print(f"Batch size: {BATCH_SIZE:,}")
    print()

    sim = AliMipsSimulator(log_handler=lambda msg: None)
    sim.setUartHandler(on_uart)
    trace_enabled = False

    try:
        sim.loadFile(FIRMWARE)
    except FileNotFoundError:
        print(f"ERROR: {FIRMWARE} not found!")
        return 1

    start_time = time.time()
    total_steps = 0
    batch_num = 0
    errors = []
    recent_end_pcs = []

    initial_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    print(f"Start PC: 0x{initial_pc:08X}")
    print(f"{'Batch':>6}  {'Steps':>12}  {'PC':>12}  {'Mode':>6}  {'UART':>5}  {'Rate':>10}  Notes")
    print("-" * 90)

    try:
        while total_steps < MAX_INSTRUCTIONS:
            pc_before = sim.mu.reg_read(UC_MIPS_REG_PC)

            # Emergency stop on NULL
            if (pc_before & ~1) == 0:
                print(f"\n[!] STOPPED: PC is NULL at step {total_steps:,}")
                errors.append(f"Step {total_steps}: PC is NULL")
                break

            # Enable tracing near crash point
            if not trace_enabled and total_steps >= TRACE_AFTER:
                trace_enabled = True
                sim.trace_instructions = True
                sim.log_handler = print
                print(f"  [Trace enabled at {total_steps:,} steps]")

            # Run a batch
            remaining = MAX_INSTRUCTIONS - total_steps
            batch = min(500 if trace_enabled else BATCH_SIZE, remaining)
            count_before = sim.instruction_count

            try:
                sim.run(max_instructions=count_before + batch)
            except Exception as e:
                err_msg = str(e)
                errors.append(f"Batch {batch_num}: {err_msg}")
                pc_err = sim.mu.reg_read(UC_MIPS_REG_PC)
                if "Jump to NULL" in err_msg:
                    print(f"\n[!] Jump to NULL at batch {batch_num}, PC=0x{pc_err:08X}")
                    break
                else:
                    print(f"\n[WARN] Error at batch {batch_num}: {err_msg}")
                    if sim.mu.reg_read(UC_MIPS_REG_PC) == pc_before:
                        sim.mu.reg_write(UC_MIPS_REG_PC, pc_before + 4)

            steps_this_batch = sim.instruction_count - count_before
            total_steps = sim.instruction_count
            batch_num += 1

            pc_after = sim.mu.reg_read(UC_MIPS_REG_PC)
            mode = sim.isa_mode.value

            now = time.time()
            elapsed = now - start_time
            rate = total_steps / max(elapsed, 0.001)

            notes = ""
            if uart_chars > 0:
                recent_text = ''.join(uart_output[-20:]).replace('\n', '\\n').replace('\r', '\\r')
                notes = f"UART: {recent_text}"

            print(f"{batch_num:>6}  {total_steps:>12,}  0x{pc_after:08X}  {mode:>6}  {uart_chars:>5}  {rate:>8,.0f}/s  {notes}")

            # Stall detection
            recent_end_pcs.append(pc_after)
            if len(recent_end_pcs) > STALL_WINDOW:
                recent_end_pcs.pop(0)
            if len(recent_end_pcs) >= STALL_WINDOW and len(set(recent_end_pcs)) == 1:
                print(f"\n[STALL] PC stuck at 0x{pc_after:08X} for {STALL_WINDOW} batches")
                errors.append(f"Stall at 0x{pc_after:08X}")
                break

            if steps_this_batch == 0:
                print(f"\n[!] No instructions executed in batch {batch_num}")
                errors.append(f"Zero instructions at 0x{pc_before:08X}")
                break

    except KeyboardInterrupt:
        print(f"\n\n[INTERRUPTED] at step {total_steps:,}")

    # ─── Summary ──────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    final_pc = sim.mu.reg_read(UC_MIPS_REG_PC)

    print(f"\n{'='*60}")
    print(f"=== SUMMARY ===")
    print(f"  Steps executed: {total_steps:,}")
    print(f"  Elapsed time:   {elapsed:.1f}s")
    print(f"  Rate:           {total_steps/max(elapsed,0.001):,.0f} instructions/sec")
    print(f"  Final PC:       0x{final_pc:08X}")
    print(f"  Final mode:     {sim.isa_mode.value}")

    if uart_chars > 0:
        uart_text = ''.join(uart_output)
        print(f"\n  UART output ({uart_chars} chars):")
        print(f"  ┌{'─'*58}┐")
        for line in uart_text.split('\n'):
            line = line.rstrip('\r')
            if len(line) > 56:
                line = line[:53] + "..."
            print(f"  │ {line:<56} │")
        print(f"  └{'─'*58}┘")
    else:
        print(f"\n  [!] NO UART OUTPUT detected!")

    if errors:
        print(f"\n  Errors ({len(errors)}):")
        for e in errors:
            print(f"    - {e}")

    print(f"\n  Registers:")
    regs = [
        ('v0', UC_MIPS_REG_V0), ('v1', UC_MIPS_REG_V1),
        ('a0', UC_MIPS_REG_A0), ('a1', UC_MIPS_REG_A1),
        ('t0', UC_MIPS_REG_T0), ('t1', UC_MIPS_REG_T1),
        ('sp', UC_MIPS_REG_SP), ('ra', UC_MIPS_REG_RA),
        ('gp', UC_MIPS_REG_GP),
    ]
    for name, reg in regs:
        print(f"    {name} = 0x{sim.mu.reg_read(reg):08X}")

    return 0 if uart_chars > 0 else 1

if __name__ == "__main__":
    sys.exit(main())
