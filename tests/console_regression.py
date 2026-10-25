"""
Shared helpers for per-dump UART console command tests (run_dump_*_console.py).

Boots a firmware dump with fast LZMA HLE, locates input_task's sys_state and
console_mode variables in unpacked MIPS32 guest RAM (plus sci_16550 / printf
routing for silent builds), and provides a clean check recorder that emits
[PASS] / [FAIL] lines for run_all_tests.py and report/index.html.
"""
import faulthandler
import os
import re
import struct
import sys
import time
from unicorn.mips_const import (
    UC_MIPS_REG_A0,
    UC_MIPS_REG_A1,
    UC_MIPS_REG_A2,
    UC_MIPS_REG_GP,
    UC_MIPS_REG_PC,
    UC_MIPS_REG_RA,
    UC_MIPS_REG_SP,
)

sys.stdout.reconfigure(encoding="utf-8")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from simulator import AliMipsSimulator

WATCHDOG_S = 600        # see ConsoleHarness.__init__

# MIPS32 signatures in unpacked guest RAM:
# - input_task's sleep(50) + sys_state check:
#     [jal <sleep>;] addiu $a0, $zero, 50; lw $a0, <sys_off>($gp); sltiu $v1, $a0, 1;
#     xori $v0, $a0, 3; sltiu $v0, $v0, 1; or $v1, $v1, $v0; bnez ...
_PAT_SYS_STATE = re.compile(
    re.escape(bytes.fromhex("32000424"))
    + b"(..)(?:"
    + re.escape(bytes.fromhex("848f0100832c030082380100422c"))
    + b"|"
    + re.escape(bytes.fromhex("828ffcff401003000324faff4310"))
    + b")",
    re.DOTALL,
)
# - console_fn's console_mode bitcheck: lbu $v0/$v1, <con_off>($gp); andi $v0/$v1, $v0/$v1, 1
_PAT_CON_MODE = re.compile(
    b"(..)(?:"
    + re.escape(bytes.fromhex("829301004230"))
    + b"|"
    + re.escape(bytes.fromhex("839301006330"))
    + b")",
    re.DOTALL,
)
# - input_task's `jal <console_fn>; nop` right after the sys_state check
_PAT_CON_JAL = re.compile(b"(...\x0c)\x00\x00\x00\x00", re.DOTALL)
# - libc_printf's 3-stub header:
#     jr $ra; sb $a0, <sci_id>($gp); jr $ra; sh $a0, <task_id>($gp); jr $ra; sb $a0, <mute>($gp)
_PAT_PRINTF_CFG = re.compile(
    b"\x08\x00\xe0\x03..\x84\xa3\x08\x00\xe0\x03..\x84\xa7\x08\x00\xe0\x03..\x84\xa3",
    re.DOTALL,
)
# - get_privilege_level stub: jr $ra; lw $v0, <priv_off>($gp)
_PAT_PRIV_GET = re.compile(b"\x08\x00\xe0\x03(..)\x82\x8f", re.DOTALL)
# - osal_delay(uint16_t us): spins on CP0 Count ($9) using magic reciprocal 0x431BDE83 or / 2000000 (0x1E8480)
_PAT_OSAL_DELAY = re.compile(
    b"\xe0\xff\xbd\x27(?:\x18\x00\xbf\xaf|\x1c\x00\xbf\xaf\x18\x00\xb2\xaf)\x14\x00\xb1\xaf\x10\x00\xb0\xaf"
    b".{16,20}(?:"
    + re.escape(bytes.fromhex("1b43023c83de4234"))
    + b"|"
    + b"\x1e\x00[\x02\x03]\x3c\x80\x84[\x42\x63]\x34"
    + b")",
    re.DOTALL,
)
_PAT_SCI_ATTACH_BODY = re.compile(
    b"(?:\x10|\x18)" + re.escape(bytes.fromhex("000324040043ac080040ac")),
    re.DOTALL,
)
_PRO_30 = bytes.fromhex("d0ffbd272800bfaf")
_PRO_28 = bytes.fromhex("d8ffbd272000bfaf")
_PAT_CANARY = bytes.fromhex("2b1a093c4d3c2935")
_PAT_ISR_EXIT = bytes.fromhex(
    "8000bd27000000000000bf8f0400bd27000000000000ba8f0400bd27000000000000bb8f0400bd270000000021e86003"
)
# - the ISR's store of the pending-IRQ mask right before it restores EPC:
#     lui $at, <hi>; sw $t1, <lo>($at); lw $k0, 0($sp); mtc0 $k0, $14
_PAT_ISR_IRQ_MASK = re.compile(
    b"(..)\\x01\\x3c(..)\\x29\\xac" + re.escape(bytes.fromhex("0000ba8f00709a40")),
    re.DOTALL,
)
_PAT_DISP_ON = re.compile(
    re.escape(bytes.fromhex("ffff42240300401c")) + b"(..)" + re.escape(bytes.fromhex("82af")),
    re.DOTALL,
)
# - lsr_dispatcher's interrupt nesting counter increment:
#     lw $v0, <nest_off>($gp); addiu $v0, $v0, 1; sw $v0, <nest_off>($gp); lui $v0, 0xb800
_PAT_LSR_NEST = re.compile(
    b"(..)\\x82\\x8f\\x01\\x00\\x42\\x24\\1\\x82\\xaf\\x00\\xb8\\x02\\x3c",
    re.DOTALL,
)
# - SEE mailbox RPC sender (`rpc_to_see` on dual-CPU SDK builds): writes a packet to
#   0xB8000200 and spins until the SEE core writes 0xFFFFFFFF back.  When the harness
#   stops the SEE core for single-task direct_call mode, stubbing this avoids hanging
#   on SEE RPC calls (e.g. C3503C otp_init in OTPPRINT).
_PAT_SEE_RPC = re.compile(
    re.escape(bytes.fromhex("b8ffbd274400bfaf4000beaf"))
    + b".{80,140}"
    + re.escape(bytes.fromhex("00b81e3c0002d637")),
    re.DOTALL,
)



def discover_sci_attach(ram: bytes):
    """Return (attach_fn, mode_fn) for sci_16550_attach and sci_mode_set in unpacked RAM."""
    m = _PAT_SCI_ATTACH_BODY.search(ram)
    assert m is not None, "failed to locate sci_16550_attach body in RAM"
    fn_a = ram.rfind(_PRO_30, m.start() - 0x250, m.start())
    assert fn_a != -1, "failed to locate sci_16550_attach prologue in RAM"
    fn_m = ram.find(_PRO_28, fn_a, fn_a + 0x700)
    assert fn_m != -1, "failed to locate sci_mode_set prologue in RAM"
    return 0x80000000 + fn_a, 0x80000000 + fn_m


def discover_console_offsets(ram: bytes):
    """Return (sys_off, con_off, con_fn, idle_addr) from unpacked MIPS32 guest RAM."""
    m_sys = _PAT_SYS_STATE.search(ram)
    assert m_sys is not None, "failed to locate input_task sys_state check in RAM"
    sys_off = struct.unpack("<h", m_sys.group(1))[0]

    con_fn = None
    m_con = None
    for m_jal in _PAT_CON_JAL.finditer(ram, m_sys.end(), m_sys.end() + 0x28):
        jal_word = struct.unpack("<I", m_jal.group(1))[0]
        cand_fn = 0x80000000 | ((jal_word & 0x03FFFFFF) << 2)
        fn_off = cand_fn - 0x80000000
        cand_con = _PAT_CON_MODE.search(ram, fn_off, fn_off + 0x200)
        if cand_con is not None:
            con_fn = cand_fn
            m_con = cand_con
            break
    if con_fn is None:
        m_jal = _PAT_CON_JAL.search(ram, m_sys.end(), m_sys.end() + 0x28)
        assert m_jal is not None, "failed to locate jal <console_fn> in input_task"
        jal_word = struct.unpack("<I", m_jal.group(1))[0]
        con_fn = 0x80000000 | ((jal_word & 0x03FFFFFF) << 2)
        m_con_list = list(_PAT_CON_MODE.finditer(ram[max(0, m_sys.start() - 0x2000) : m_sys.start()]))
        assert m_con_list, "failed to locate console_mode check before input_task in RAM"
        m_con = m_con_list[-1]
    con_off = struct.unpack("<h", m_con.group(1))[0]

    idle_off = ram.find(bytes.fromhex("1800bd27ffff001000000000"), 0x2000)
    if idle_off != -1:
        idle_addr = 0x80000000 + idle_off + 4
    else:
        idle_off = ram.find(bytes.fromhex("ffff001000000000"), 0x10000)
        assert idle_off != -1, "failed to locate OSAL idle loop (b .) in RAM"
        idle_addr = (0x80000000 + idle_off) & ~3
    return sys_off, con_off, con_fn, idle_addr


class ConsoleHarness:
    """Helper wrapping AliMipsSimulator for driving and asserting UART console commands."""

    def __init__(
        self,
        dump_path,
        title,
        boot_insns=6_000_000,
        attach_sci=None,
        direct_call=False,
        mask_timer=False,
        boot_until=None,
        boot_step=250_000,
    ):
        """boot_insns   -- instructions to boot before taking the console over;
        boot_until   -- optionally, a predicate on the UART output so far: the
                        boot stops (checked every boot_step instructions, after
                        boot_step at the earliest) as soon as it holds, at
                        boot_insns at the latest.  The firmware's progress per
                        instruction follows host timing, so a milestone it
                        prints is a steadier take-over point than a count."""
        self.dump_path = dump_path
        self.title = title
        self.direct_call = direct_call
        self.mask_timer = mask_timer
        self.t0 = time.time()
        self.checks = []
        self.uart_out = []

        print(f"=== Console Commands Test: {title} ({dump_path}) ===")
        # A console test takes 10-60 s; one stuck in the emulation for 10
        # minutes prints where (every thread's stack) and exits with an error
        # rather than stall the whole run_all_tests run (re-armed per attempt).
        faulthandler.dump_traceback_later(WATCHDOG_S, exit=True)
        self.sim = AliMipsSimulator(log_handler=lambda m: None)
        self.sim.setSPIDump(False)
        self.sim.setI2CDump(False)
        self.sim.lzma_insns_per_byte = 0
        self.sim.setUartHandler(lambda ch: self.uart_out.append(ch))
        self.sim.loadFile(dump_path)
        if boot_until is None:
            self.sim.run(max_instructions=boot_insns)
        else:
            while self.sim.instruction_count < boot_insns:
                self.sim.run(max_instructions=min(boot_insns, self.sim.instruction_count + boot_step))
                if boot_until("".join(self.uart_out)):
                    break

        self.gp = self.sim.mu.reg_read(UC_MIPS_REG_GP)
        self.init_sp = self.sim.mu.reg_read(UC_MIPS_REG_SP)
        self.ram = bytes(self.sim._ram_view[:0x01000000])
        self.boot_banner = "".join(self.uart_out)

        sys_off, con_off, self.con_fn, self.idle_addr = discover_console_offsets(self.ram)
        self.sys_addr = (self.gp + sys_off) & 0xFFFFFFFF
        self.con_addr = (self.gp + con_off) & 0xFFFFFFFF
        self.irq_mask_addr = None
        self.nest_addr = None

        if direct_call and mask_timer:
            if self.sim.mu.reg_read(UC_MIPS_REG_PC) not in (self.idle_addr, self.idle_addr + 4):
                self.sim.stop_instr = self.idle_addr
                try:
                    self.sim.run(max_instructions=self.sim.instruction_count + 2_000_000)
                finally:
                    self.sim.stop_instr = None
            self.sim._insn_rate = 1_000_000.0
            self.sim._counted_slices = self.sim.calibration_slices
            if getattr(self.sim.chip, "see", None) is not None:
                self.sim.chip.see._stop_core()
                m_rpc = _PAT_SEE_RPC.search(self.ram)
                if m_rpc is not None:
                    self.sim.poke(0x80000000 + m_rpc.start(), bytes.fromhex("0800e00321100000"))
            self.sim._ic_lines = 0
            self.init_sp = 0x80E00000
            self.sim.mu.reg_write(UC_MIPS_REG_SP, self.init_sp)
            self.sim.mu.reg_write(UC_MIPS_REG_RA, self.idle_addr)
            self.sim.mu.reg_write(UC_MIPS_REG_PC, self.idle_addr)
            self.sim.cp0_status = (self.sim.cp0_status | 0x0801) & ~0x8006
            self.sim._write_native_status(self.sim.mu, self.sim.cp0_status)
            m_delay = _PAT_OSAL_DELAY.search(self.ram)
            if m_delay is not None:
                self.sim.poke(0x80000000 + m_delay.start(), bytes.fromhex("0800e00300000000"))
            ic = self.ram.find(_PAT_CANARY)
            if ic != -1 and self.ram[ic - 0x8C : ic - 0x84] == bytes.fromhex("e8ffbd271400bfaf"):
                self.sim.poke(0x80000000 + ic - 0x80, bytes.fromhex("2b00001000000000"))
            ie = self.ram.find(_PAT_ISR_EXIT)
            if ie != -1:
                self.sim.poke(0x80000000 + ie + 0x3A, b"\x00\x10")
                m_mask = None
                for m_mask in _PAT_ISR_IRQ_MASK.finditer(self.ram, max(0, ie - 0x100), ie):
                    pass                                    # (the last store before the exit)
                if m_mask is not None:
                    hi_m = struct.unpack("<H", m_mask.group(1))[0]
                    lo_m = struct.unpack("<h", m_mask.group(2))[0]
                    self.irq_mask_addr = ((hi_m << 16) + lo_m) & 0xFFFFFFFF
            m_nest = _PAT_LSR_NEST.search(self.ram)
            if m_nest is not None:
                nest_off = struct.unpack("<h", m_nest.group(1))[0]
                self.nest_addr = (self.gp + nest_off) & 0xFFFFFFFF
            self._reset_isr_state()
            m_disp = _PAT_DISP_ON.search(self.ram)
            if m_disp is not None:
                self.sim.poke(0x80000000 + m_disp.start() + 4, b"\x00\x00\x00\x00")
                lock_off = struct.unpack("<h", m_disp.group(1))[0]
                self.sim.poke((self.gp + lock_off) & 0xFFFFFFFF, (0).to_bytes(4, "little"))
            self.sim._tb_flush_needed = True

        # (a silent build may still emit a stray control byte, e.g. '\x01')
        prints_text = any(c.isprintable() and not c.isspace() for c in self.boot_banner)
        self._attach = None
        if attach_sci is not None and (attach_sci is not True or not prints_text):
            attach_fn, mode_fn = (
                discover_sci_attach(self.ram) if attach_sci is True else attach_sci
            )
            m_printf = _PAT_PRINTF_CFG.search(self.ram)
            assert m_printf is not None, f"missing printf config stubs in {dump_path}"
            self._attach = (0x80000000 + m_printf.start(), attach_fn, mode_fn)
            self.attach_uart()

        self.sim.poke(self.sys_addr, (2).to_bytes(4, "little"))
        self.sim.poke(self.con_addr, b"\x02")

    def _reset_isr_state(self):
        if self.irq_mask_addr is not None:
            self.sim.poke(self.irq_mask_addr, (0).to_bytes(4, "little"))
        if self.nest_addr is not None:
            self.sim.poke(self.nest_addr, (0).to_bytes(4, "little"))

    def attach_uart(self):
        """Silent builds: route libc_printf to UART 0 (sci id 0, all tasks,
        unmuted) and attach / configure sci_16550[0] at 115200 8N1."""
        printf_fn, attach_fn, mode_fn = self._attach
        self.call_guest_fn(printf_fn, 0)
        self.call_guest_fn(printf_fn + 8, 0xFFFF)
        self.call_guest_fn(printf_fn + 16, 0)
        self.call_guest_fn(attach_fn, 1)
        self.call_guest_fn(mode_fn, 0, 115200, 0)

    def handshake(self, tries=3):
        """Send "comtest" (the listener echoes it) and return the echo.  On a
        silent build taken over while its start-up still reconfigures the
        UART, the listener can stay deaf: then the UART is attached again and
        the handshake retried, at most `tries` times; still deaf, ConsoleDeaf
        is raised (run_with_retry boots once more, at another point of the
        host-timed start-up).  Returns (echo, tries used)."""
        resp = ""
        for attempt in range(1, tries + 1):
            resp = self.send("comtest", max_slices=8, stop_on=("comtest",))
            if resp == "comtest":
                return resp, attempt
            self.sim._uart_rx_queue.clear()
            self._reset_isr_state()
            if self._attach is not None:
                self.attach_uart()
            self.sim.poke(self.sys_addr, (2).to_bytes(4, "little"))
            self.sim.poke(self.con_addr, b"\x02")
        raise ConsoleDeaf(f"no 'comtest' echo after {tries} tries ({resp!r}); "
                          f"UART banner at take-over {self.boot_banner[-40:]!r}")

    def call_guest_fn(self, fn_addr, a0=0, a1=0, a2=0, insns=50_000, max_insns=1_000_000):
        """Call a guest function with interrupts off, returning into the idle
        loop: run `insns` at a time until it gets there (at most max_insns)."""
        clr_mask = 0x8007 if self.mask_timer else 0x07
        self.sim.cp0_status &= ~clr_mask
        self.sim._write_native_status(self.sim.mu, self.sim.cp0_status)
        self.sim.mu.reg_write(UC_MIPS_REG_A0, a0)
        self.sim.mu.reg_write(UC_MIPS_REG_A1, a1)
        self.sim.mu.reg_write(UC_MIPS_REG_A2, a2)
        self.sim.mu.reg_write(UC_MIPS_REG_RA, self.idle_addr)
        self.sim.mu.reg_write(UC_MIPS_REG_PC, fn_addr)
        end = self.sim.instruction_count + max_insns
        while self.sim.instruction_count < end:
            self.sim.run(max_instructions=self.sim.instruction_count + insns)
            if self.sim.mu.reg_read(UC_MIPS_REG_PC) in (self.idle_addr, self.idle_addr + 4):
                break

    @property
    def console_mode(self) -> int:
        return self.sim.peek(self.con_addr, 1)[0]

    def activate(self, trigger="startconsole", tries=3):
        """Send the activation trigger until the console is up (console_mode
        4), at most `tries` times: after a long boot the first read of the
        hijacked task can miss input (host-timed emulation); on a silent
        build the UART is attached again between tries.  Raises ConsoleDeaf
        if it never comes up.  Returns the response of the successful attempt
        and the attempts used."""
        resp = ""
        for attempt in range(1, tries + 1):
            resp = self.send(trigger)
            if self.console_mode == 4:
                return resp, attempt
            self.sim._uart_rx_queue.clear()         # (drop a half-read trigger)
            self._reset_isr_state()
            if self._attach is not None and not resp:
                self.attach_uart()
            self.sim.poke(self.sys_addr, (2).to_bytes(4, "little"))
            self.sim.poke(self.con_addr, b"\x02")
        raise ConsoleDeaf(f"{trigger!r} did not activate the console after {tries} tries ({resp!r})")

    def send(
        self,
        data,
        max_slices=16,
        slice_insns=200_000,
        stop_on=(
            ">",
            "Enter name:",
            "Enter flag:",
            "Enter val :",
            "... ",
            "?\r\n",
            "...\r\n",
            "***\r\n",
            "Rebooting...\r\n",
            "comtest",
        ),
        direct_call=None,
    ) -> str:
        use_direct = self.direct_call if direct_call is None else direct_call
        self.uart_out.clear()
        clr_mask = 0x8006 if self.mask_timer else 0x06
        if int.from_bytes(self.sim.peek(self.sys_addr, 4), "little") != 2:
            self.sim.poke(self.sys_addr, (2).to_bytes(4, "little"))
        # If console_mode is 2 (e.g. right after EXIT\r or comtest) and the
        # previous console_fn call has not yet returned to idle_addr, let it
        # finish its trailing sci_16550_read_tm and unlock rx_mutex first.
        if use_direct and self.mask_timer and self.console_mode == 2:
            for _ in range(16):
                if self.sim.mu.reg_read(UC_MIPS_REG_PC) in (self.idle_addr, self.idle_addr + 4):
                    break
                self.sim.run(max_instructions=self.sim.instruction_count + slice_insns)
        raw = data if isinstance(data, bytes) else data.encode("latin-1")
        self.sim.setUartReceiveData(raw, delay_instructions=50)
        at_idle = self.sim.mu.reg_read(UC_MIPS_REG_PC) in (self.idle_addr, self.idle_addr + 4)
        if use_direct and (self.console_mode == 2 or at_idle):
            if self.mask_timer:
                self.sim.mu.reg_write(UC_MIPS_REG_SP, self.init_sp)
            self.sim.mu.reg_write(UC_MIPS_REG_RA, self.idle_addr)
            self.sim.mu.reg_write(UC_MIPS_REG_PC, self.con_fn)
            self._reset_isr_state()
            self.sim.cp0_status = (self.sim.cp0_status | 0x0801) & ~clr_mask
        else:
            # Preserve EXL (0x02) if the CPU stopped mid-ISR so eret can complete
            # before another interrupt is injected on top of it.
            self.sim.cp0_status = (self.sim.cp0_status | 0x0801) & ~(clr_mask & ~0x02)
        self.sim._write_native_status(self.sim.mu, self.sim.cp0_status)
        # max_slices bounds a quiet wait; while the firmware is making progress
        # -- still printing (a long listing on a loaded host, where a slice
        # holds fewer guest instructions) or still reading `data` -- it is
        # extended, up to 8x, so the tail of one command's output does not
        # spill into the next one's.
        n = 0
        prev = None
        while n < max_slices * 8:
            at_idle = self.sim.mu.reg_read(UC_MIPS_REG_PC) in (self.idle_addr, self.idle_addr + 4)
            if use_direct and self.mask_timer and at_idle:
                self.sim.mu.reg_write(UC_MIPS_REG_SP, self.init_sp)
                self.sim.mu.reg_write(UC_MIPS_REG_RA, self.idle_addr)
                self.sim.mu.reg_write(UC_MIPS_REG_PC, self.con_fn)
                self._reset_isr_state()
                self.sim.cp0_status = (self.sim.cp0_status | 0x0801) & ~clr_mask
            else:
                self.sim.cp0_status = (self.sim.cp0_status | 0x0801) & ~(clr_mask & ~0x02)
            self.sim._write_native_status(self.sim.mu, self.sim.cp0_status)
            self.sim.run(max_instructions=self.sim.instruction_count + slice_insns)
            n += 1
            s = "".join(self.uart_out)
            if stop_on and any(s.endswith(tok) for tok in stop_on):
                break
            state = (len(s), len(self.sim._uart_rx_queue))
            if n >= max_slices and state == prev:
                break
            prev = state
        return "".join(self.uart_out)

    def check(self, desc: str, ok: bool, detail: str = ""):
        status = "PASS" if ok else "FAIL"
        suffix = f" ({detail})" if detail and not ok else ""
        print(f"  [{status}] {desc}{suffix}")
        self.checks.append((desc, bool(ok)))

    def finish(self):
        ok = all(hit for _, hit in self.checks)
        n_pass = sum(1 for _, hit in self.checks if hit)
        elapsed = time.time() - self.t0
        print(
            f"\n[{'PASS' if ok else 'FAIL'}] {self.title}: "
            f"{n_pass}/{len(self.checks)} checks passed ({elapsed:.1f}s)"
        )
        if not ok:
            sys.exit(1)


class ConsoleDeaf(Exception):
    """The firmware's UART listener never answered (see ConsoleHarness.handshake)."""


def run_with_retry(fn):
    """Run a console test, booting once more after a simulator crash (UcError)
    or a listener that stayed deaf (ConsoleDeaf): both depend on where the
    host-timed start-up was when the harness took over."""
    for attempt in (1, 2):
        try:
            fn()
            return
        except Exception as e:
            if attempt == 2 or ("UcError" not in type(e).__name__ and not isinstance(e, ConsoleDeaf)):
                raise
            print(f"[WARN] {'console deaf' if isinstance(e, ConsoleDeaf) else 'simulator stopped'} ({e}); retrying")
