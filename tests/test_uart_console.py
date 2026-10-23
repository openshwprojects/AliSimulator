"""
End-to-end test of the interactive UART monitor console ("startconsole" /
PALANTIR) and standard ALi SDK "comtest" handshake across all five supported
ALi SoC families (M3602, M3801, M3821, M3503, M3606).

Covers:
1. Booting dump_maciej.bin (M3602) into the main application ($gp = 0x806FA0F4)
   and verifying the SDK/application UART banner.
2. Verifying the "comtest" factory trigger and activating the interactive UART
   console by sending "startconsole" over UART (handler 0x8001C88C in
   input_task 0x8001D074).
3. Verifying Backspace (0x08) line editing and case-insensitive command input.
4. Verifying built-in diagnostic and interactive commands: HELP (all 18 public
   commands), VERSION, HEAP, MAINCODE, FLAG (setting flag F0=1), TIME, CLS,
   and unknown command error handling.
5. Verifying hidden privilege escalation commands MAGICKEY (level 1) and
   PALANTIR (level 3, checked by 0x80085184), unlocking privileged commands
   HMSG (60-entry control message table), GPIOCONFIG (configuring GPIO 10 as
   output high in MMIO 0xB8000058 / 0xB8000054), and SENDMSG.
6. Verifying RCU emulation mode (0x80094988): injecting ASCII ('x' ->
   V_KEY_MUTE) and VT100 arrow escape sequences ('\\x1b[B' -> V_KEY_DOWN)
   over UART, then leaving RCU mode with ESC ('\\x1b').
7. Deactivating the console with EXIT (returning console_mode to 2) and
   re-activating it with "startconsole".
8. Multi-dump / multi-SoC UART console and "comtest" verification across:
   - Ali_3801_Globo_DVBT_dump SPI 4mb.bin (M3801, V.0127 DVB-T PVR)
   - OPTICUM HD T90/STB_HD_T90_N2-3_1.3.2PVR_2014-01-05.abs (M3801, V.0132 DVB-T PVR)
   - Opticum Blue R265 Lite/T2GEN265_1.1.5-2022-08-01.abs (M3821, V.0115 DVB-T2 PVR)
   - GLOBO HD-XS2/Sw_Globo_HD-XS2_Reta_pol_1.3.5_2015-06-22.abs (M3503 silent build, SW: 0135 POL_NETR_PVR)
   - OPTICUM X110P/Software_Conax_X110p_PL_SMART_HD+_1.3.4_RC3_2015-01-23.abs (M3606 silent build, SW: 0134 SMART HD+)
   - CABLETECH URZ0083/URZ0083_V1.2.5.abs (M3801 standard SDK build: "comtest" echo)
"""
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


def main():
    t0 = time.time()
    sim = AliMipsSimulator(log_handler=lambda m: None)
    sim.setSPIDump(False)
    sim.setI2CDump(False)
    uart_out = []
    sim.setUartHandler(lambda ch: uart_out.append(ch))
    sim.loadFile("dump_maciej.bin")

    # Boot into the main application (LzmaDecode HLE adds ~29M virtual
    # instructions in 0.1s; 38M reaches maincode with $gp = 0x806FA0F4).
    sim.run(max_instructions=38_000_000)
    gp = sim.mu.reg_read(UC_MIPS_REG_GP)
    banner = "".join(uart_out)
    assert gp == 0x806FA0F4, f"unexpected $gp: 0x{gp:08X}"
    assert "Application version 1.0.0@SDK4.0ba" in banner, f"missing app banner in {banner!r}"

    # Enable input_task normal state (-26332($gp) = 2) and UART listener state
    # (-16840($gp) = 2, set by 0x8001C220(2) at 0x800120C4 / 0x8003DC88).
    SYS_STATE_ADDR = gp - 26332
    CONSOLE_MODE_ADDR = gp - 16840
    RCU_MODE_ADDR = gp - 0x60BB
    PRIV_ADDR = gp - 0x6130

    sim.poke(SYS_STATE_ADDR, (2).to_bytes(4, "little"))
    sim.poke(CONSOLE_MODE_ADDR, b"\x02")

    def send_uart(data, max_slices=12, slice_insns=200_000,
                  stop_on=(">", ":", "...\r\n", "***\r\n", "?\r\n")):
        uart_out.clear()
        if int.from_bytes(sim.peek(SYS_STATE_ADDR, 4), "little") != 2:
            sim.poke(SYS_STATE_ADDR, (2).to_bytes(4, "little"))
        raw = data if isinstance(data, bytes) else data.encode("latin-1")
        sim.setUartReceiveData(raw, delay_instructions=50)
        for _ in range(max_slices):
            sim.run(max_instructions=sim.instruction_count + slice_insns)
            s = "".join(uart_out)
            if stop_on and any(s.endswith(tok) for tok in stop_on):
                break
        return "".join(uart_out)

    # 1. Verify "comtest" trigger in listener mode (console_mode == 2)
    resp = send_uart("comtest", max_slices=6, stop_on=("comtest",))
    assert resp == "comtest", f"expected 'comtest' echo, got {resp!r}"
    assert sim.peek(CONSOLE_MODE_ADDR, 1)[0] == 2

    # 2. Activate interactive console with "startconsole"
    resp = send_uart("startconsole")
    assert "***  CONSOLE ACTIVATED  ***" in resp and resp.endswith(">"), f"activation failed: {resp!r}"
    assert sim.peek(CONSOLE_MODE_ADDR, 1)[0] == 4, "expected console_mode == 4"

    # 3. Verify HELP lists all 18 public commands (MAGICKEY & PALANTIR are hidden)
    resp = send_uart("help\r")
    for cmd_name in (
        "DELETE", "TOUCH", "READ", "RCU", "FLAG", "MAINCODE", "CHANNELS",
        "VERSION", "CLS", "HEAP", "SENDMSG", "HMSG", "TIME", "GPIOCONFIG",
        "ADDDUMMY", "HELP", "EXIT", "REBOOT",
    ):
        assert cmd_name in resp, f"missing {cmd_name} in HELP output: {resp!r}"
    assert "PALANTIR" not in resp and "MAGICKEY" not in resp

    # 4. Verify Backspace (0x08) line editing + case-insensitive VERSION command
    resp = send_uart("verX\x08sion\r")
    assert "verX\x08 \x08sion\r\n" in resp, f"expected backspace echo in {resp!r}"
    assert "V.0112 DVB-T PVR (0002)>" in resp, f"unexpected VERSION output: {resp!r}"

    # 5. Verify HEAP and MAINCODE diagnostics
    resp = send_uart("HEAP\r")
    assert "HEAP:" in resp and "/27695" in resp, f"unexpected HEAP output: {resp!r}"

    resp = send_uart("MAINCODE\r")
    assert "1764656/2359296 [74%]" in resp, f"unexpected MAINCODE output: {resp!r}"

    # 6. Verify interactive FLAG command (set F0 = 1)
    resp = send_uart("FLAG\r")
    assert "F0:0, F1:0" in resp and resp.endswith("Enter flag:"), f"unexpected FLAG prompt: {resp!r}"
    resp = send_uart("0\r")
    assert resp.endswith("Enter val :"), f"unexpected FLAG val prompt: {resp!r}"
    resp = send_uart("1\r")
    assert "F0:1, F1:0" in resp and resp.endswith(">"), f"expected F0:1 in {resp!r}"

    # 7. Verify TIME command and cancelling new time entry
    resp = send_uart("TIME\r")
    assert "TIME:" in resp and "If set new time?" in resp, f"unexpected TIME output: {resp!r}"
    resp = send_uart("n")
    assert "Wrong value!" in resp and resp.endswith(">"), f"unexpected TIME abort output: {resp!r}"

    # 8. Verify unknown command error message
    resp = send_uart("UNKNOWN\r")
    assert "UNKNOWN: Unknown command!" in resp and resp.endswith(">"), f"unexpected UNKNOWN output: {resp!r}"

    # 9. Verify privilege gating: HMSG & SENDMSG are silent at privilege 0,
    #    MAGICKEY sets privilege 1, PALANTIR sets privilege 3 and unlocks
    #    HMSG, GPIOCONFIG, and SENDMSG.
    assert int.from_bytes(sim.peek(PRIV_ADDR, 4), "little") == 0
    resp = send_uart("HMSG\r")
    assert resp == "HMSG\r\n>", f"HMSG should be gated before PALANTIR, got {resp!r}"
    resp = send_uart("SENDMSG\r")
    assert resp == "SENDMSG\r\n>", f"SENDMSG should be gated before PALANTIR, got {resp!r}"

    resp = send_uart("MAGICKEY\r")
    assert resp == "MAGICKEY\r\n>"
    assert int.from_bytes(sim.peek(PRIV_ADDR, 4), "little") == 1, "MAGICKEY should set priv=1"

    resp = send_uart("PALANTIR\r")
    assert resp == "PALANTIR\r\n>"
    assert int.from_bytes(sim.peek(PRIV_ADDR, 4), "little") == 3, "PALANTIR should set priv=3"

    resp = send_uart("HMSG\r", max_slices=15)
    assert "Lista MSG:" in resp and "000\tCTRL_MSG_SUBTYPE_KEY = 0" in resp, f"missing HMSG header: {resp[:120]!r}"
    assert "159\tCTRL_MSG_ENTER_FACTORY" in resp and resp.endswith(">"), f"missing HMSG tail: {resp[-120:]!r}"

    resp = send_uart("GPIOCONFIG\r", stop_on=("... ",))
    assert resp.endswith("Wybierz GPIO... "), f"expected GPIOCONFIG pin prompt, got {resp!r}"
    resp = send_uart("10\r", stop_on=("output)",))
    assert "Wybierz DIR... (1 - output)" in resp, f"expected GPIOCONFIG dir prompt, got {resp!r}"
    resp = send_uart("1\r", stop_on=("... ",))
    assert "Wybierz VAL... " in resp, f"expected GPIOCONFIG val prompt, got {resp!r}"
    resp = send_uart("1\r")
    assert resp.endswith(">"), f"expected prompt after GPIOCONFIG, got {resp!r}"
    gpio_dir = int.from_bytes(sim.mu.mem_read(0xB8000058, 4), "little")
    gpio_do = int.from_bytes(sim.mu.mem_read(0xB8000054, 4), "little")
    assert (gpio_dir & (1 << 10)) != 0 and (gpio_do & (1 << 10)) != 0, (
        f"expected GPIO 10 dir & output bit set: dir=0x{gpio_dir:08X}, do=0x{gpio_do:08X}"
    )

    resp = send_uart("SENDMSG\r", stop_on=("... ",))
    assert resp.endswith("Input MSG code... "), f"expected SENDMSG code prompt, got {resp!r}"
    resp = send_uart("27\r", stop_on=("... ",))
    assert "Input MSG param... " in resp, f"expected SENDMSG param prompt, got {resp!r}"
    resp = send_uart("0\r")
    assert resp.endswith(">"), f"expected prompt after SENDMSG, got {resp!r}"

    # 10. Verify RCU emulation mode (ASCII key 'x' -> MUTE, VT100 '\x1b[B' -> DOWN, '\x1b' -> exit)
    resp = send_uart("RCU\r")
    assert "Enter RCU emulation mode" in resp and sim.peek(RCU_MODE_ADDR, 1)[0] == 1

    resp = send_uart("x", max_slices=6, stop_on=("\r\n",))
    assert "Key receive: 120[78]" in resp, f"expected RCU 'x' key echo, got {resp!r}"

    resp = send_uart("\x1b[B", max_slices=8, stop_on=("66[42]\r\n",))
    assert "27[1B]/91[5B]/66[42]" in resp, f"expected VT100 DOWN echo, got {resp!r}"

    resp = send_uart("\x1b")
    assert "Leave RCU emulation mode..." in resp and resp.endswith(">"), f"expected RCU exit, got {resp!r}"
    assert sim.peek(RCU_MODE_ADDR, 1)[0] == 0

    # 11. Verify CLS screen clear and EXIT console deactivation + re-activation
    resp = send_uart("CLS\r")
    assert resp == "CLS\r\n\x1b[H\x1b[2J>", f"unexpected CLS output: {resp!r}"

    resp = send_uart("EXIT\r")
    assert "*** CONSOLE DEACTIVATED ***" in resp and sim.peek(CONSOLE_MODE_ADDR, 1)[0] == 2

    # Let the trailing 1000-tick UART read in 0x8001CB68 time out so 0x8001C88C
    # returns to input_task and re-enters the console_mode == 2 branch.
    sim.run(max_instructions=sim.instruction_count + 200_000)

    resp = send_uart("startconsole")
    assert "***  CONSOLE ACTIVATED  ***" in resp and sim.peek(CONSOLE_MODE_ADDR, 1)[0] == 4

    # 12. Verify UART console and "comtest" across M3801, M3821, M3503, and M3606 dumps
    test_multi_dump_uart_console()

    print(
        f"[PASS] UART console: startconsole, 15 commands, PALANTIR privilege escalation, "
        f"GPIO MMIO control, RCU emulation, and multi-SoC console/comtest verified ({time.time() - t0:.1f}s)"
    )


# MIPS32 signatures in unpacked guest RAM:
# - input_task's sleep(50) + sys_state check:
#     addiu $a0, $zero, 50; lw $a0, <sys_off>($gp); sltiu $v1, $a0, 1;
#     xori $v0, $a0, 3; sltiu $v0, $v0, 1; or $v1, $v1, $v0; bnez ...
_PAT_SYS_STATE = re.compile(
    re.escape(bytes.fromhex("32000424"))
    + b"(..)"
    + re.escape(bytes.fromhex("848f0100832c030082380100422c")),
    re.DOTALL,
)
# - console_fn's console_mode bitcheck: lbu $v0, <con_off>($gp); andi $v0, $v0, 1
_PAT_CON_MODE = re.compile(b"(..)" + re.escape(bytes.fromhex("829301004230")), re.DOTALL)
# - input_task's return check right after jal <console_fn>; nop:
#     move $v1, $v0; addiu $v0, $v0, -1; sltiu $v0, $v0, 2
_PAT_AFTER_CON_JAL = re.compile(re.escape(bytes.fromhex("21184000ffff42240200422c")), re.DOTALL)
# - libc_printf's 3-stub header:
#     jr $ra; sb $a0, <sci_id>($gp); jr $ra; sh $a0, <task_id>($gp); jr $ra; sb $a0, <mute>($gp)
_PAT_PRINTF_CFG = re.compile(
    b"\x08\x00\xe0\x03..\x84\xa3\x08\x00\xe0\x03..\x84\xa7\x08\x00\xe0\x03..\x84\xa3",
    re.DOTALL,
)


def _discover_console_offsets(ram: bytes):
    """Return (sys_off, con_off, con_fn, idle_addr) from unpacked MIPS32 guest RAM."""
    m_sys = _PAT_SYS_STATE.search(ram)
    assert m_sys is not None, "failed to locate input_task sys_state check in RAM"
    sys_off = struct.unpack("<h", m_sys.group(1))[0]

    m_con_list = list(_PAT_CON_MODE.finditer(ram[max(0, m_sys.start() - 0x1000) : m_sys.start()]))
    assert m_con_list, "failed to locate console_mode check before input_task in RAM"
    con_off = struct.unpack("<h", m_con_list[-1].group(1))[0]

    m_jal = _PAT_AFTER_CON_JAL.search(ram, m_sys.start(), m_sys.start() + 0x60)
    assert m_jal is not None, "failed to locate jal <console_fn> in input_task"
    jal_word = struct.unpack("<I", ram[m_jal.start() - 8 : m_jal.start() - 4])[0]
    con_fn = 0x80000000 | ((jal_word & 0x03FFFFFF) << 2)

    idle_off = ram.find(bytes.fromhex("1800bd27ffff001000000000"), 0x2000)
    if idle_off != -1:
        idle_addr = 0x80000000 + idle_off + 4
    else:
        idle_off = ram.find(bytes.fromhex("ffff001000000000"), 0x10000)
        assert idle_off != -1, "failed to locate OSAL idle loop (b .) in RAM"
        idle_addr = (0x80000000 + idle_off) & ~3
    return sys_off, con_off, con_fn, idle_addr


def _boot_fast_dump(dump_path, boot_insns=6_000_000, attach_sci=None):
    """Boot a dump with zero-cost LZMA HLE and return (sim, send_uart_fn, ram)."""
    sim = AliMipsSimulator(log_handler=lambda m: None)
    sim.setSPIDump(False)
    sim.setI2CDump(False)
    sim.lzma_insns_per_byte = 0
    uart_out = []
    sim.setUartHandler(lambda ch: uart_out.append(ch))
    sim.loadFile(dump_path)
    sim.run(max_instructions=boot_insns)

    gp = sim.mu.reg_read(UC_MIPS_REG_GP)
    ram = bytes(sim._ram_view[:0x01000000])
    sys_off, con_off, con_fn, idle_addr = _discover_console_offsets(ram)

    def call_guest_fn(fn_addr, a0=0, a1=0, a2=0, insns=50_000):
        sim.cp0_status &= ~0x07
        sim._write_native_status(sim.mu, sim.cp0_status)
        sim.mu.reg_write(UC_MIPS_REG_A0, a0)
        sim.mu.reg_write(UC_MIPS_REG_A1, a1)
        sim.mu.reg_write(UC_MIPS_REG_A2, a2)
        sim.mu.reg_write(UC_MIPS_REG_RA, idle_addr)
        sim.mu.reg_write(UC_MIPS_REG_PC, fn_addr)
        sim.run(max_instructions=sim.instruction_count + insns)

    # For silent retail/Conax builds that omit sci_16550_attach() at boot,
    # route libc_printf to UART0 and attach/configure sci_16550[0] at 115200 8N1.
    if attach_sci is not None:
        attach_fn, mode_fn = attach_sci
        m_printf = _PAT_PRINTF_CFG.search(ram)
        assert m_printf is not None, f"missing printf config stubs in {dump_path}"
        printf_fn = 0x80000000 + m_printf.start()
        call_guest_fn(printf_fn, 0)
        call_guest_fn(printf_fn + 8, 0xFFFF)
        call_guest_fn(printf_fn + 16, 0)
        call_guest_fn(attach_fn, 1)
        call_guest_fn(mode_fn, 0, 115200, 0)

    sys_addr = (gp + sys_off) & 0xFFFFFFFF
    con_addr = (gp + con_off) & 0xFFFFFFFF
    sim.poke(sys_addr, (2).to_bytes(4, "little"))
    sim.poke(con_addr, b"\x02")
    sim.cp0_status = (sim.cp0_status | 0x0801) & ~0x06
    sim._write_native_status(sim.mu, sim.cp0_status)

    def send_uart(data, direct_call=False, max_slices=12, slice_insns=200_000,
                  stop_on=(">", "comtest")):
        uart_out.clear()
        sim.cp0_status = (sim.cp0_status | 0x0801) & ~0x06
        sim._write_native_status(sim.mu, sim.cp0_status)
        if int.from_bytes(sim.peek(sys_addr, 4), "little") != 2:
            sim.poke(sys_addr, (2).to_bytes(4, "little"))
        raw = data if isinstance(data, bytes) else data.encode("latin-1")
        sim.setUartReceiveData(raw, delay_instructions=50)
        if direct_call and (
            sim.peek(con_addr, 1)[0] == 2 or sim.mu.reg_read(UC_MIPS_REG_PC) == idle_addr
        ):
            sim.mu.reg_write(UC_MIPS_REG_RA, idle_addr)
            sim.mu.reg_write(UC_MIPS_REG_PC, con_fn)
        for _ in range(max_slices):
            sim.run(max_instructions=sim.instruction_count + slice_insns)
            s = "".join(uart_out)
            if stop_on and any(s.endswith(tok) for tok in stop_on):
                break
        return "".join(uart_out)

    return sim, send_uart, ram, con_addr


def test_multi_dump_uart_console():
    """Verify live UART console and 'comtest' across M3801, M3821, M3503, and M3606.

    Uses console_regression.ConsoleHarness with the same settings as the
    per-dump run_dump_*_console.py tests."""
    import gc
    from console_regression import ConsoleHarness, run_with_retry

    # 1. ALi M3801 (Globo N3 SPI dump): comtest + startconsole + VERSION
    def _step1():
        h = ConsoleHarness("Ali_3801_Globo_DVBT_dump SPI 4mb.bin", "Globo N3 (M3801)",
                           direct_call=True, mask_timer=True)
        assert b"startconsole\x00" in h.ram and b"PALANTIR\x00" in h.ram
        assert h.handshake()[0] == "comtest"
        act, _ = h.activate()
        assert "***  CONSOLE ACTIVATED  ***" in act and h.console_mode == 4, f"Globo activation: {act!r}"
        ver = h.send("VERSION\r")
        assert "V.0127 DVB-T PVR (0002)>" in ver, f"unexpected Globo M3801 VERSION: {ver!r}"
    run_with_retry(_step1)
    gc.collect()

    # 2. ALi M3801 (Opticum HD T90): comtest + startconsole + VERSION
    def _step2():
        h = ConsoleHarness("OPTICUM HD T90/STB_HD_T90_N2-3_1.3.2PVR_2014-01-05.abs", "Opticum HD T90 (M3801)",
                           direct_call=True, mask_timer=True)
        assert b"startconsole\x00" in h.ram and b"PALANTIR\x00" in h.ram
        assert h.handshake()[0] == "comtest"
        act, _ = h.activate()
        assert "***  CONSOLE ACTIVATED  ***" in act and h.console_mode == 4, f"T90 activation: {act!r}"
        ver = h.send("VERSION\r")
        assert "V.0132 DVB-T PVR (0002)>" in ver, f"unexpected T90 VERSION: {ver!r}"
    run_with_retry(_step2)
    gc.collect()

    # 3. ALi M3821 (Opticum Blue R265 Lite DVB-T2): startconsole + VERSION + M3821 HELP
    def _step3():
        h = ConsoleHarness("Opticum Blue R265 Lite/T2GEN265_1.1.5-2022-08-01.abs", "Opticum Blue R265 Lite 1.1.5 (M3821)",
                           boot_insns=8_000_000, direct_call=True, mask_timer=True)
        assert b"startconsole\x00" in h.ram and b"PRINT_MEM_LAYOUT\x00" in h.ram
        assert h.handshake()[0] == "comtest"
        act, _ = h.activate()
        assert "***  CONSOLE ACTIVATED  ***" in act and h.console_mode == 4, f"R265 Lite activation: {act!r}"
        ver = h.send("VERSION\r")
        assert "V.0115 DVB-T2 PVR (0002)>" in ver, f"unexpected R265 Lite VERSION: {ver!r}"
        hlp = h.send("HELP\r")
        assert "PWMGPIO" in hlp and "PRINT_MEM_LAYOUT" in hlp, f"unexpected R265 Lite HELP: {hlp!r}"
    run_with_retry(_step3)
    gc.collect()

    # 4. ALi M3503 (Globo HD-XS2 DVB-S2 silent build): attach sci_16550 + startconsole + VERSION + HELP
    def _step4():
        h = ConsoleHarness("GLOBO HD-XS2/Sw_Globo_HD-XS2_Reta_pol_1.3.5_2015-06-22.abs", "Globo HD-XS2 Reta 1.3.5 (M3503)",
                           boot_insns=6_000_000, attach_sci=(0x8012ED1C, 0x8012F344), direct_call=True, mask_timer=True)
        assert b"startconsole\x00" in h.ram and b"Navigation\x00" in h.ram and b"PALANTIR\x00" in h.ram
        assert h.handshake()[0] == "comtest"
        act, _ = h.activate()
        assert "***  CONSOLE ACTIVATED  ***" in act and h.console_mode == 4, f"HD-XS2 activation: {act!r}"
        ver = h.send("VERSION\r")
        assert "SW: 0135 POL_NETR_PVR (0162)" in ver, f"unexpected HD-XS2 VERSION: {ver!r}"
        hlp = h.send("HELP\r")
        assert "* * *Navigation* * *" in hlp and "SCREEN" in hlp and "HRCU" in hlp, (
            f"unexpected HD-XS2 HELP: {hlp!r}"
        )
    run_with_retry(_step4)
    gc.collect()

    # 5. ALi M3606 (Opticum HD X110p DVB-S2): startconsole + VERSION
    def _step5():
        h = ConsoleHarness("OPTICUM X110P/Software_Conax_X110p_PL_SMART_HD+_1.3.4_RC3_2015-01-23.abs",
                           "Opticum HD X110p 1.3.4 (M3606)", boot_insns=10_000_000, direct_call=True, mask_timer=True)
        assert b"startconsole\x00" in h.ram and b"PALANTIR\x00" in h.ram
        assert h.handshake()[0] == "comtest"
        act, _ = h.activate()
        assert "***  CONSOLE ACTIVATED  ***" in act and h.console_mode == 4, f"X110p activation: {act!r}"
        ver = h.send("VERSION\r")
        assert "SW: 0134 SMART HD+ (0004)" in ver, f"unexpected X110p VERSION: {ver!r}"
    run_with_retry(_step5)
    gc.collect()

    # 6. ALi M3801 standard SDK build without startconsole (Cabletech URZ0083): comtest echo
    sim, send, ram, con_addr = _boot_fast_dump("CABLETECH URZ0083/URZ0083_V1.2.5.abs")
    assert b"startconsole" not in ram and b"comtest\x00" in ram
    assert send("comtest") == "comtest", "expected 'comtest' echo on URZ0083"


if __name__ == "__main__":
    from console_regression import run_with_retry
    run_with_retry(main)

