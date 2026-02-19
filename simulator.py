from unicorn import *
from unicorn.mips_const import *
from capstone import *
import sys
from enum import Enum
from dataclasses import dataclass
from typing import Optional
from mips16_decoder import MIPS16Decoder

class ISAMode(Enum):
    """ISA mode enumeration"""
    MIPS32 = 'mips32'
    MIPS16 = 'mips16'


@dataclass
class StepResult:
    """Result of a single step execution"""
    address: int
    instruction: str
    operands: str
    next_pc: int
    mode_before: str
    mode_after: str
    is_branch: bool = False
    is_call: bool = False
    is_return: bool = False
    mode_switched: bool = False
    instruction_size: int = 4


class AliMipsSimulator:
    def __init__(self, rom_size=4*1024*1024, ram_size=128*1024*1024, log_handler=None):
        self.rom_size = rom_size
        self.ram_size = ram_size
        self.base_addr = 0xAFC00000
        self.mu = None
        self.md = None
        self.uart_callback = None
        self.spi_callback = None
        self.log_callback = log_handler

        self.instruction_count = 0
        self.visit_counts = {}
        self.instruction_sizes = {}
        self.trace_instructions = False
        self.stop_instr = None
        self.break_on_printf = False
        self.max_instructions = 10000000
        self.is_syncing = False
        self.prev_executed_pc = None
        self.current_executed_pc = None
        
        # NEW: Explicit ISA mode tracking
        self.isa_mode = ISAMode.MIPS32
        
        # Call stack tracking for step_out
        self.call_stack = []
        
        # Debug flag - only log after MIPS16 mode entered
        self.debug_enabled = False
        
        # Breakpoints
        self.breakpoints = set()
        self.is_stepping = False
        self.pc_history = []
        self.history_size = 50

        # Simulated CP0 Count register (hardware cycle counter)
        # Unicorn doesn't expose CP0 Count via reg_read/reg_write, so we track it ourselves.
        self.cp0_count = 0
        self._step_count = 0  # Hook-based step counter for precise single-stepping

        # Set of addresses observed executing as MIPS32 within the MIPS16 region.
        # Populated by _hook_code when Unicorn reports size=4 at a MIPS16-range address.
        # Used by _detect_isa_mode to correctly re-enter MIPS32 code after emu_stop().
        self.mips32_islands = set()

        # Tracks whether the current emu_start() call was started in MIPS32 mode.
        # Used by _hook_code to correctly populate mips32_islands without
        # confusing MIPS16 extended (4-byte) instructions with MIPS32.
        self._emu_started_as_mips32 = False

        # SPI Flash Controller emulation (matches flash_raw_sl_c.c)
        # Hardware registers:
        #   SF_INS (+0x98) = command/instruction register
        #   SF_FMT (+0x99) = format register (which SPI bus phases are active)
        #   SF_DUM (+0x9A) = dummy/data register
        #   SF_CFG (+0x9B) = configuration register
        # SF_FMT bit flags:
        #   0x01 SF_HIT_DATA  - data phase active
        #   0x02 SF_HIT_DUMM  - dummy cycle active
        #   0x04 SF_HIT_ADDR  - address phase active
        #   0x08 SF_HIT_CODE  - command/opcode phase active
        #   0x40 SF_CONT_RD   - continuous read mode
        #   0x80 SF_CONT_WR   - continuous write mode
        self._spi_jedec_id = [0xEF, 0x40, 0x16]  # Winbond W25Q64 (capacity 0x16 is in device table)
        self._spi_ins = 0x03       # SF_INS: current SPI command (default: normal read)
        self._spi_fmt = 0x0D       # SF_FMT: default = HIT_CODE|HIT_ADDR|HIT_DATA (normal read)
        self._spi_dum = 0x00       # SF_DUM: dummy/data register
        self._spi_cfg = 0x00       # SF_CFG: config register
        self._spi_status = 0x00    # Flash status register (bit0=WIP, bits[5:2]=BP)
        self._spi_wel = False      # Write Enable Latch
        self._spi_response = []    # queued response bytes for memory-mapped reads
        self._spi_resp_idx = 0     # current read index into response
        self._last_flash_read_page = -1  # for throttled flash read logging

        # Track last instruction's size and address from _hook_code.
        # Used by _detect_isa_mode to detect JALX-induced mode switches:
        # after JALX, Unicorn internally switches to MIPS32 and reports size=4
        # for the target instructions, even though we started in MIPS16 mode.
        self._last_hook_size = 0
        self._last_hook_addr = 0

        self._init_unicorn()
        self._init_capstone()


        self.gpr_map = [
            UC_MIPS_REG_ZERO, UC_MIPS_REG_AT, UC_MIPS_REG_V0, UC_MIPS_REG_V1,
            UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3,
            UC_MIPS_REG_T0, UC_MIPS_REG_T1, UC_MIPS_REG_T2, UC_MIPS_REG_T3,
            UC_MIPS_REG_T4, UC_MIPS_REG_T5, UC_MIPS_REG_T6, UC_MIPS_REG_T7,
            UC_MIPS_REG_S0, UC_MIPS_REG_S1, UC_MIPS_REG_S2, UC_MIPS_REG_S3,
            UC_MIPS_REG_S4, UC_MIPS_REG_S5, UC_MIPS_REG_S6, UC_MIPS_REG_S7,
            UC_MIPS_REG_T8, UC_MIPS_REG_T9, UC_MIPS_REG_K0, UC_MIPS_REG_K1,
            UC_MIPS_REG_GP, UC_MIPS_REG_SP, UC_MIPS_REG_FP, UC_MIPS_REG_RA
        ]

    def _init_unicorn(self):
        # Initialize Unicorn (MIPS32 + Little Endian)
        self.mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
        # Set MIPS32R2 CPU model (24Kf) to match ALI hardware
        self.mu.ctl_set_cpu_model(UC_CPU_MIPS32_24KF)
        
        # Map memory
        self.log(f"Mapping memory at {hex(self.base_addr)}")
        self.mu.mem_map(self.base_addr, self.rom_size)
        
        # Map mirror
        self.log(f"Mapping mirror at 0x0FC00000")
        self.mu.mem_map(0x0FC00000, self.rom_size)
        
        # Shared RAM Buffer (128MB as per device spec)
        import ctypes
        self.ram_buffer = ctypes.create_string_buffer(self.ram_size)
        ram_ptr = ctypes.addressof(self.ram_buffer)
        
        # Map RAM aliases to same buffer
        self.log(f"Mapping Shared RAM at 0x80000000, 0xA0000000, 0x00000000")
        self.mu.mem_map_ptr(0x80000000, self.ram_size, UC_PROT_ALL, ram_ptr)
        self.mu.mem_map_ptr(0xA0000000, self.ram_size, UC_PROT_ALL, ram_ptr)
        self.mu.mem_map_ptr(0x00000000, self.ram_size, UC_PROT_ALL, ram_ptr)
        
        # Map MMIO
        MMIO_SIZE = 0x01000000
        mmio_regions = [
            (0x18000000, "Physical"),
            (0x98000000, "KSEG0 cached"),
            (0xB8000000, "KSEG1 uncached"),
        ]
        
        for base, name in mmio_regions:
            try:
                self.mu.mem_map(base, MMIO_SIZE)
                self.mu.mem_write(base, b'\x00' * MMIO_SIZE)
                self.log(f"Mapped {name} peripherals at {hex(base)}")
            except UcError as e:
                self.log(f"Warning: {name} at {hex(base)} - {e}")

        # Set UART LSR
        try:
            self.mu.mem_write(0xb8018305, b'\x20')
            # Mirror LSR to Physical and KSEG0 to avoid polling loops
            self.mu.mem_write(0x18018305, b'\x20')
            self.mu.mem_write(0x98018305, b'\x20')
            self.log("Initialized UART LSR at 0xb8018305 (and mirrors) to 0x20")
        except Exception as e:
            self.log(f"Failed to init UART LSR: {e}")

        # Set Magic Value at 0xb8000002 for testing
        try:
            val_bytes = b'\x11\x38' # 0x3811 Little Endian
            self.mu.mem_write(0xb8000002, val_bytes)
            self.mu.mem_write(0x18000002, val_bytes)
            self.mu.mem_write(0x98000002, val_bytes)
            self.log("Initialized magic value 0x3811 at 0xb8000002 (and mirrors)")
        except Exception as e:
            self.log(f"Failed to init magic value: {e}")

        # Hooks
        self.mu.hook_add(UC_HOOK_MEM_INVALID, self._hook_mem_invalid)
        self.mu.hook_add(UC_HOOK_CODE, self._hook_instruction_fix)
        # Memory Sync Hook (KSEG0 <-> KSEG1)
        # KSEG0: 0x80000000, KSEG1: 0xA0000000
        # We hook both regions to sync writes
        kseg0_end = 0x80000000 + self.ram_size - 1
        kseg1_end = 0xA0000000 + self.ram_size - 1
        phys_end = self.ram_size - 1
        # RAM Sync Hooks REMOVED (Handled by mem_map_ptr)

        # UART Hooks (Aliased)
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_uart_write, begin=0x18018300, end=0x18018305)
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_uart_write, begin=0x98018300, end=0x98018305)
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_uart_write, begin=0xb8018300, end=0xb8018305)

        # SPI Flash Controller Register Hooks
        # Hook BOTH register bases: 0xB8000098 (default) and 0xB802E098 (M3329E rev>=5)
        # Each base has 4 registers: SF_INS(+0x98), SF_FMT(+0x99), SF_DUM(+0x9A), SF_CFG(+0x9B)
        for base in [0x18000098, 0x98000098, 0xB8000098,
                     0x1802E098, 0x9802E098, 0xB802E098]:
            self.mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_spi_write, begin=base, end=base + 3)
            self.mu.hook_add(UC_HOOK_MEM_READ, self._hook_spi_read, begin=base, end=base + 3)

        # SPI Flash Memory-Mapped Data Hooks (SYS_FLASH_BASE_ADDR)
        # Read hook covers the full range to log flash read offsets.
        # Passthrough path is cheap (page-change throttled logging).
        # Writes need full range for erase/program operations.
        for flash_base in [self.base_addr, 0x0FC00000]:
            self.mu.hook_add(UC_HOOK_MEM_READ, self._hook_spi_flash_read,
                             begin=flash_base, end=flash_base + self.rom_size - 1)
            self.mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_spi_flash_write,
                             begin=flash_base, end=flash_base + self.rom_size - 1)

        self.mu.hook_add(UC_HOOK_CODE, self._hook_code)
        
        # CP0 Status configuration
        try:
            status = 0x10400000 # CU0=1, BEV=1
            self.mu.reg_write(UC_MIPS_REG_CP0_STATUS, status)
            self.log(f"Set CP0 Status = 0x{status:08X}")
        except Exception as e:
            self.log(f"Warning: Could not set CP0 Status: {e}")

    def _init_capstone(self):
        self.md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)

    def setLogHandler(self, handler):
        self.log_callback = handler

    def setUartHandler(self, handler):
        self.uart_callback = handler

    def setSpiHandler(self, handler):
        self.spi_callback = handler

    def addBreakpoint(self, address):
        self.breakpoints.add(address)
        self.log(f"Breakpoint added at 0x{address:08X}")

    def removeBreakpoint(self, address):
        if address in self.breakpoints:
            self.breakpoints.remove(address)
            self.log(f"Breakpoint removed at 0x{address:08X}")

    def log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
        else:
            print(msg)

    def _uart_log(self, value):
        if self.uart_callback:
            # Pass the character code directly, let the handler decide format
            self.uart_callback(chr(value & 0xFF))
        else:
            print(chr(value & 0xFF), end='', flush=True)

    # SPI command name lookup for readable log output
    _SPI_CMD_NAMES = {
        0x03: "Read", 0x0B: "Fast Read", 0x9F: "JEDEC Read ID",
        0x05: "Read Status", 0xAB: "Release Power Down",
        0x90: "Read Mfr/Dev ID", 0x06: "WREN", 0x04: "WRDI",
        0x01: "Write Status", 0x02: "Page Program", 0xAD: "AAI Program",
        0xD8: "Sector Erase", 0xC7: "Chip Erase",
    }

    def _spi_log(self, msg):
        if self.spi_callback:
            self.spi_callback(msg)
        else:
            print(f"[SPI] {msg}", flush=True)

    def loadFile(self, filename):
        self.log(f"Loading {filename}...")
        with open(filename, "rb") as f:
            code = f.read()
        
        # Auto-expand ROM mapping if file is larger than rom_size
        if len(code) > self.rom_size:
            new_size = (len(code) + 0xFFF) & ~0xFFF  # Round up to 4KB page
            self.log(f"File size (0x{len(code):X}) exceeds rom_size (0x{self.rom_size:X}), expanding to 0x{new_size:X}")
            # Unmap old regions and remap with new size
            self.mu.mem_unmap(self.base_addr, self.rom_size)
            self.mu.mem_unmap(0x0FC00000, self.rom_size)
            self.rom_size = new_size
            self.mu.mem_map(self.base_addr, self.rom_size)
            self.mu.mem_map(0x0FC00000, self.rom_size)
        
        self.mu.mem_write(self.base_addr, code)
        self.mu.mem_write(0x0FC00000, code)
        
        # Set PC to start address
        self.mu.reg_write(UC_MIPS_REG_PC, self.base_addr)
        
        # Re-initialize globals if re-running
        self.instruction_count = 0
        self.visit_counts = {}
        self.last_lui_addr = None

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        access_types = {
            16: "READ", 17: "WRITE", 18: "FETCH",
            19: "READ_UNMAPPED", 20: "WRITE_UNMAPPED", 21: "FETCH_UNMAPPED",
            22: "WRITE_PROT", 23: "READ_PROT", 24: "FETCH_PROT",
        }
        pc = uc.reg_read(UC_MIPS_REG_PC)
        atype = access_types.get(access, f"UNKNOWN({access})")
        
        # Always print to stderr so crash details are never lost
        import sys as _sys
        print(f"\n[!] INVALID MEMORY ACCESS", file=_sys.stderr, flush=True)
        print(f"    Type: {atype}", file=_sys.stderr, flush=True)
        print(f"    Address: 0x{address:08X}", file=_sys.stderr, flush=True)
        print(f"    Size: {size}", file=_sys.stderr, flush=True)
        print(f"    PC: 0x{pc:08X}", file=_sys.stderr, flush=True)
        
        # Dump all GPRs for debugging
        gpr_names = [
            "zero","at","v0","v1","a0","a1","a2","a3",
            "t0","t1","t2","t3","t4","t5","t6","t7",
            "s0","s1","s2","s3","s4","s5","s6","s7",
            "t8","t9","k0","k1","gp","sp","fp","ra"
        ]
        print(f"    --- Register Dump ---", file=_sys.stderr, flush=True)
        for i, name in enumerate(gpr_names):
            val = uc.reg_read(self.gpr_map[i])
            print(f"    {name:4s} = 0x{val:08X}", file=_sys.stderr, flush=True)
        
        # Disassemble instruction at PC
        try:
            code = uc.mem_read(pc, 4)
            print(f"    --- Instruction at PC ---", file=_sys.stderr, flush=True)
            print(f"    Bytes: {' '.join(f'{b:02x}' for b in code)}", file=_sys.stderr, flush=True)
            for i in self.md.disasm(bytes(code), pc):
                print(f"    {i.mnemonic}\t{i.op_str}", file=_sys.stderr, flush=True)
        except Exception as e:
            print(f"    (could not disasm: {e})", file=_sys.stderr, flush=True)
        
        # Also send to log handler
        if address == 0 and access in [18, 21]:  # FETCH or FETCH_UNMAPPED
            self.log(f"\n[!] STOPPED: Jump to NULL (0x0) detected!")
        else:
            self.log(f"\n[!] INVALID MEMORY ACCESS")
            self.log(f"    Type: {atype}")
            self.log(f"    Address: 0x{address:08X}")
        self.log(f"    Size: {size}")
        self.log(f"    PC: 0x{pc:08X}")
        return False

    def _hook_uart_write(self, uc, access, address, size, value, user_data):
        # 0xb8018300 is base, store happens at offset 0 usually
        # Check all aliases: 0x18018300, 0x98018300, 0xB8018300
        if (address & 0xFFFFF) == 0x18300:
            self._uart_log(value)
            # Set LSR bit 5 (0x20 = Transmitter Holding Register Empty)
            # so firmware's uart_write_char doesn't timeout and retry 3x.
            # LSR is at UART base + 5 (SCI_16550_ULSR = 5).
            lsr_addr = (address & ~0xFFFFF) | 0x18305
            uc.mem_write(lsr_addr, b'\x20')

    def _hook_spi_write(self, uc, access, address, size, value, user_data):
        """Handle writes to SPI flash controller registers.
        
        Matches the hardware register interface from flash_raw_sl_c.c:
          SF_INS (+0x98) — SPI command/instruction
          SF_FMT (+0x99) — format (which bus phases are active)
          SF_DUM (+0x9A) — dummy/data register
          SF_CFG (+0x9B) — configuration
        """
        offset = address & 0xF
        if offset == 0x8:  # SF_INS — SPI instruction register
            self._spi_ins = value & 0xFF
            self._last_flash_read_page = -1  # Reset so next passthrough read always logs
            # Queue response based on command (response read via memory-mapped access)
            cmd = self._spi_ins
            cmd_name = self._SPI_CMD_NAMES.get(cmd, f"Unknown")
            pc = uc.reg_read(UC_MIPS_REG_PC)
            self._spi_log(f"CMD 0x{cmd:02X} ({cmd_name}) [PC=0x{pc:08X}]")
            if cmd == 0x9F:  # JEDEC Read ID (RDID)
                # Returns 3-byte manufacturer/type/capacity, padded to 4 for word reads
                self._spi_response = list(self._spi_jedec_id) + [0x00]
                self._spi_resp_idx = 0
            elif cmd == 0x05:  # Read Status Register (RDSR)
                # Return current status: bit0=WIP(busy), bits[5:2]=BP(block protect)
                self._spi_response = [self._spi_status]
                self._spi_resp_idx = 0
            elif cmd == 0xAB:  # Release from Deep Power Down / Read Electronic ID
                # Returns electronic signature (capacity byte), padded
                self._spi_response = [self._spi_jedec_id[2], 0x00, 0x00, 0x00]
                self._spi_resp_idx = 0
            elif cmd == 0x90:  # Read Manufacturer/Device ID
                self._spi_response = [self._spi_jedec_id[0], self._spi_jedec_id[2],
                                      self._spi_jedec_id[0], self._spi_jedec_id[2]]
                self._spi_resp_idx = 0
            elif cmd == 0x06:  # Write Enable (WREN)
                self._spi_wel = True
                self._spi_status |= 0x02  # Set WEL bit in status
                self._spi_response = []
                self._spi_resp_idx = 0
            elif cmd == 0x04:  # Write Disable (WRDI)
                self._spi_wel = False
                self._spi_status &= ~0x02  # Clear WEL bit
                self._spi_response = []
                self._spi_resp_idx = 0
            elif cmd == 0x01:  # Write Status Register (WRSR)
                # Data byte will come via memory-mapped write
                self._spi_response = []
                self._spi_resp_idx = 0
            elif cmd == 0x03:  # Normal Read — passthrough mode
                self._spi_response = []
                self._spi_resp_idx = 0
            elif cmd == 0x0B:  # Fast Read — passthrough mode
                self._spi_response = []
                self._spi_resp_idx = 0
            elif cmd == 0x02:  # Page Program (PP)
                self._spi_response = []
                self._spi_resp_idx = 0
            elif cmd == 0xAD:  # AAI Word Program (SST)
                self._spi_response = []
                self._spi_resp_idx = 0
            elif cmd == 0xD8:  # Sector Erase
                self._spi_response = []
                self._spi_resp_idx = 0
            elif cmd == 0xC7:  # Chip Erase
                self._spi_response = []
                self._spi_resp_idx = 0
            else:
                # Unknown command — no response
                self._spi_response = []
                self._spi_resp_idx = 0
        elif offset == 0x9:  # SF_FMT — format register
            self._spi_fmt = value & 0xFF
            # Decode format flags for logging
            flags = []
            if value & 0x01: flags.append("DATA")
            if value & 0x02: flags.append("DUMM")
            if value & 0x04: flags.append("ADDR")
            if value & 0x08: flags.append("CODE")
            if value & 0x40: flags.append("CONT_RD")
            if value & 0x80: flags.append("CONT_WR")
            self._spi_log(f"  FMT 0x{value & 0xFF:02X} [{' | '.join(flags)}]")
        elif offset == 0xA:  # SF_DUM — dummy/data register
            self._spi_dum = value & 0xFF
        elif offset == 0xB:  # SF_CFG — config register
            self._spi_cfg = value & 0xFF

    def _hook_spi_read(self, uc, access, address, size, value, user_data):
        """Handle reads from SPI flash controller registers.
        
        Firmware does volatile readback of registers it just wrote
        (e.g. write SF_INS then read SF_INS back). Return the stored values.
        """
        offset = address & 0xF
        if offset == 0x8:  # SF_INS readback
            uc.mem_write(address, bytes([self._spi_ins]))
        elif offset == 0x9:  # SF_FMT readback
            uc.mem_write(address, bytes([self._spi_fmt]))
        elif offset == 0xA:  # SF_DUM readback
            uc.mem_write(address, bytes([self._spi_dum]))
        elif offset == 0xB:  # SF_CFG readback
            uc.mem_write(address, bytes([self._spi_cfg]))

    def _spi_is_passthrough(self):
        """Check if SPI controller is in normal flash read mode (passthrough).
        
        In normal read mode, reads from SYS_FLASH_BASE_ADDR return actual
        flash content. The controller is in passthrough when:
          SF_INS = 0x03 (Read) or 0x0B (Fast Read)
        
        Note: SF_HIT_ADDR may or may not be set. In CONT_RD mode the firmware
        sets FMT=0x0D (DATA|ADDR|CODE) for the first read, then FMT=0x09
        (DATA|CODE) for sequential reads without address phase.
        """
        return self._spi_ins in (0x03, 0x0B)

    def _hook_spi_flash_read(self, uc, access, address, size, value, user_data):
        """Handle reads from the memory-mapped flash region (SYS_FLASH_BASE_ADDR).
        
        When the SPI controller is in command mode (not passthrough), reads
        from the flash address space return SPI response data instead of
        flash content. This implements the hardware behavior where:
        
          write_uint8(SF_FMT, SF_HIT_CODE | SF_HIT_DATA);  // command mode
          write_uint8(SF_INS, 0x9F);                         // JEDEC Read ID
          result = *(volatile UINT32 *)SYS_FLASH_BASE_ADDR;  // read response
        """
        if self._spi_is_passthrough():
            # Log flash read offset (throttled: only when 64KB sector changes)
            if address >= self.base_addr:
                flash_offset = address - self.base_addr
            elif address >= 0x0FC00000:
                flash_offset = address - 0x0FC00000
            else:
                flash_offset = address
            sector = flash_offset >> 16  # 64KB sectors
            if self._last_flash_read_page != sector:
                self._last_flash_read_page = sector
                self._spi_log(f"  FLASH READ @ 0x{flash_offset:06X} (sector {sector})")
            return  # Normal read mode — let ROM content pass through

        # Command mode — inject SPI response data
        if self._spi_resp_idx < len(self._spi_response):
            if size == 4:  # Word read (e.g. JEDEC ID)
                resp = bytearray(4)
                for i in range(4):
                    if self._spi_resp_idx < len(self._spi_response):
                        resp[i] = self._spi_response[self._spi_resp_idx]
                        self._spi_resp_idx += 1
                    else:
                        resp[i] = 0x00
                uc.mem_write(address, bytes(resp))
                self._spi_log(f"  RESP [{size}B]: {' '.join(f'{b:02X}' for b in resp)}")
            elif size == 2:  # Half-word read
                resp = bytearray(2)
                for i in range(2):
                    if self._spi_resp_idx < len(self._spi_response):
                        resp[i] = self._spi_response[self._spi_resp_idx]
                        self._spi_resp_idx += 1
                    else:
                        resp[i] = 0x00
                uc.mem_write(address, bytes(resp))
                self._spi_log(f"  RESP [{size}B]: {' '.join(f'{b:02X}' for b in resp)}")
            else:  # Byte read (e.g. status register)
                byte_val = self._spi_response[self._spi_resp_idx]
                self._spi_resp_idx += 1
                uc.mem_write(address, bytes([byte_val]))
                self._spi_log(f"  RESP [1B]: {byte_val:02X}")
        else:
            # No more response data — return 0x00 (flash idle / not busy)
            uc.mem_write(address, b'\x00' * size)

    def _hook_spi_flash_write(self, uc, access, address, size, value, user_data):
        """Handle writes to the memory-mapped flash region (SYS_FLASH_BASE_ADDR).
        
        Memory-mapped writes trigger SPI command execution:
          - WREN/WRDI (cmd 0x06/0x04): trigger via write to any flash address
          - WRSR (cmd 0x01): the write data is the new status register value
          - Chip/Sector Erase (cmd 0xC7/0xD8): triggered by write
          - Page Program (cmd 0x02): write data byte to flash
        """
        if self._spi_is_passthrough():
            return  # Normal mode — writes go to ROM (ignored in emulator)

        # Compute flash offset from access address
        # Firmware does: ((volatile UINT8 *)flash_base_addr)[flash_offset] = data
        if address >= self.base_addr:
            flash_offset = address - self.base_addr
        elif address >= 0x0FC00000:
            flash_offset = address - 0x0FC00000
        else:
            flash_offset = address

        cmd = self._spi_ins
        cmd_name = self._SPI_CMD_NAMES.get(cmd, f"0x{cmd:02X}")
        if cmd == 0x06:  # WREN — trigger
            self._spi_wel = True
            self._spi_status |= 0x02
            self._spi_log(f"  EXEC {cmd_name}")
        elif cmd == 0x04:  # WRDI — trigger
            self._spi_wel = False
            self._spi_status &= ~0x02
            self._spi_log(f"  EXEC {cmd_name}")
        elif cmd == 0x01:  # WRSR — write status register
            if self._spi_wel:
                self._spi_status = value & 0xFF
                self._spi_wel = False
                self._spi_status &= ~0x02  # Clear WEL after write
                self._spi_log(f"  EXEC {cmd_name} = 0x{value & 0xFF:02X}")
        elif cmd == 0xC7:  # Chip Erase — acknowledge
            self._spi_log(f"  EXEC {cmd_name}")
        elif cmd == 0xD8:  # Sector Erase — acknowledge
            self._spi_log(f"  EXEC {cmd_name} @ flash[0x{flash_offset:06X}]")
        elif cmd == 0x02:  # Page Program — acknowledge
            self._spi_log(f"  EXEC {cmd_name} @ flash[0x{flash_offset:06X}] = 0x{value & 0xFF:02X}")
        elif cmd == 0xAD:  # AAI Word Program — acknowledge
            self._spi_log(f"  EXEC {cmd_name} @ flash[0x{flash_offset:06X}] = 0x{value & 0xFFFF:04X}")





    def _hook_code(self, uc, address, size, user_data):
        # Increment simulated CP0 Count register (hardware cycle counter)
        # Real MIPS increments Count every other clock cycle.
        # Without this, firmware timeout loops polling MFC0 reg 9 never exit.
        self.cp0_count = (self.cp0_count + 2) & 0xFFFFFFFF

        # Stuck-PC detection: if Unicorn fires the hook at the same address twice
        # in a row, it failed to execute the instruction (unsupported MIPS16 opcode).
        # Manually emulate and stop so run() re-enters from the new PC.
        if address == self._last_hook_addr and size == self._last_hook_size and size == 2:
            if self._emulate_mips16_manual(address):
                uc.emu_stop()
                return

        # Hook-based single-stepping: Unicorn's count=1 counts Translation Blocks,
        # not individual instructions. For tight MIPS16 loops, a whole loop body
        # is one TB, so count=1 executes the full loop. To step exactly 1 instruction,
        # we track how many instructions have fired since emu_start and stop after the first.
        if self.is_stepping:
            self._step_count += 1
            if self._step_count > 1:
                uc.emu_stop()
                return

        # Record MIPS32 addresses within the MIPS16 range for _detect_isa_mode.
        # _emu_started_as_mips32 (set in run() before emu_start) distinguishes
        # real MIPS32 from MIPS16 extended (both report size=4).
        # If we see size=2 while _emu_started_as_mips32 is True, a JALX mode
        # switch occurred within this emu_start batch — clear the flag to stop
        # polluting mips32_islands with MIPS16 addresses.
        if self._emu_started_as_mips32:
            if size == 2:
                # MIPS32 never has 2-byte instructions — we switched to MIPS16
                self._emu_started_as_mips32 = False
            elif address & 0x3:
                # Not 4-byte aligned → can't be MIPS32, must be MIPS16 extended/JAL
                self._emu_started_as_mips32 = False
            elif self.is_mips16_addr(address):
                self.mips32_islands.add(address)
        
        # Track actual ISA mode based on Unicorn's execution:
        # - size==2 → definitely MIPS16
        # - size==4 and _emu_started_as_mips32 still True → MIPS32
        # - size==4 and _emu_started_as_mips32 False → MIPS16 extended/JAL
        if size == 2:
            self._tracked_isa_mode = ISAMode.MIPS16
        elif self._emu_started_as_mips32:
            self._tracked_isa_mode = ISAMode.MIPS32
        else:
            self._tracked_isa_mode = ISAMode.MIPS16
        
        # Track last instruction size/address for _detect_isa_mode
        self._last_hook_size = size
        self._last_hook_addr = address

        # Track history for jumps
        if not hasattr(self, 'current_executed_pc'): self.current_executed_pc = None
        self.prev_executed_pc = self.current_executed_pc
        self.current_executed_pc = address

        # PC History
        self.pc_history.append(address)
        if len(self.pc_history) > self.history_size:
            self.pc_history.pop(0)

        # Track visit count
        if address not in self.visit_counts:
            self.visit_counts[address] = 0
            # Track size on first visit (or every visit?)
            if not hasattr(self, 'instruction_sizes'): self.instruction_sizes = {}
            self.instruction_sizes[address] = size
        
        self.visit_counts[address] += 1
        self.instruction_sizes[address] = size # Ensure latest size is stored
        
        if self.trace_instructions:
            code_bytes = uc.mem_read(address, size)
            try:
                # Handle MIPS16 instructions (size == 2)
                if size == 2:
                    mnemonic, operands = MIPS16Decoder.decode(code_bytes)
                    bytes_str = ' '.join(f'{b:02x}' for b in code_bytes)
                    loop_str = f" [LOOP {self.visit_counts[address]}]" if self.visit_counts[address] > 1 else ""
                    self.log(f"0x{address:08X}: {bytes_str:<15} {mnemonic}\t{operands}{loop_str}")
                else:
                    # Standard MIPS32 disassembly
                    for i in self.md.disasm(code_bytes, address):
                        bytes_str = ' '.join(f'{b:02x}' for b in i.bytes)
                        loop_str = f" [LOOP {self.visit_counts[address]}]" if self.visit_counts[address] > 1 else ""
                        self.log(f"0x{i.address:08X}: {bytes_str:<15} {i.mnemonic}\t{i.op_str}{loop_str}")
            except: pass

        if not self.is_stepping:
            hit = False
            if self.stop_instr is not None and address == self.stop_instr:
                hit = True
                self.log(f"\n[STOP] Reached stop address: 0x{address:08X}")
            elif address in self.breakpoints:
                hit = True
                self.log(f"\n[BREAKPOINT] Hit at 0x{address:08X}")
            
            if hit:
                uc.emu_stop()
                return
            
        self.instruction_count += 1
        if self.max_instructions and self.instruction_count >= self.max_instructions:
            uc.emu_stop()

    def _hook_instruction_fix(self, uc, address, size, user_data):
        # NOTE: JALX and MIPS16 instructions handled natively by Unicorn
        # MIPS16 stuck-PC handling now done in _hook_code (fires after this hook)
        
        # Skip 16-bit MIPS16 instructions (handled by _emulate_mips16_manual)
        if size != 4:
            return

        try:
            insn_bytes = uc.mem_read(address, 4)

            # ---- MIPS16 Extended Instruction Handling ----
            # EXTEND prefix: bits 15:11 of first halfword == 11110 (0x1E)
            # Unicorn reports size=4 for these, same as MIPS32, but they use
            # a completely different encoding. We detect the EXTEND prefix and
            # manually emulate memory operations targeting MMIO, since Unicorn's
            # MIPS16 engine crashes (UC_ERR_EXCEPTION) on some extended stores.
            word1 = int.from_bytes(insn_bytes[0:2], byteorder='little')
            if (word1 >> 11) & 0x1F == 0x1E:
                word2 = int.from_bytes(insn_bytes[2:4], byteorder='little')
                ext_10_5 = (word1 >> 5) & 0x3F
                ext_15_11 = word1 & 0x1F
                op2 = (word2 >> 11) & 0x1F
                rx_code = (word2 >> 8) & 0x7
                ry_code = (word2 >> 5) & 0x7
                imm5 = word2 & 0x1F

                # Register-relative memory operations
                # Loads: LB(0x10) LH(0x11) LW(0x13) LBU(0x14) LHU(0x15)
                # Stores: SB(0x18) SH(0x19) SW(0x1B)
                mem_ops = {0x10, 0x11, 0x13, 0x14, 0x15, 0x18, 0x19, 0x1B}
                if op2 not in mem_ops:
                    return  # Not a memory op, let Unicorn handle

                rx_gpr = self.MIPS16_REG_MAP[rx_code]
                ry_gpr = self.MIPS16_REG_MAP[ry_code]

                # Full 16-bit signed offset from EXTEND + instruction immediate
                full_imm = (ext_15_11 << 11) | (ext_10_5 << 5) | imm5
                if full_imm & 0x8000:
                    full_imm -= 0x10000

                base_val = uc.reg_read(self.gpr_map[rx_gpr])
                target = (base_val + full_imm) & 0xFFFFFFFF

                # Only intercept MMIO accesses
                is_mmio = (0x18000000 <= target < 0x19000000) or \
                          (0x98000000 <= target < 0x99000000) or \
                          (0xB8000000 <= target < 0xB9000000)
                if not is_mmio:
                    return

                # Check if target is an SPI controller register
                spi_reg_bases = [0x18000098, 0x98000098, 0xB8000098,
                                 0x1802E098, 0x9802E098, 0xB802E098]
                is_spi_reg = any(base <= target <= base + 3 for base in spi_reg_bases)

                # Check if target is in the flash memory-mapped region
                flash_bases = [self.base_addr, 0x0FC00000]
                is_flash_region = any(fb <= target < fb + self.rom_size for fb in flash_bases)

                # Determine store size from opcode
                store_ops = {0x18: 1, 0x19: 2, 0x1B: 4}  # SB, SH, SW
                load_ops = {0x10: (1, True), 0x14: (1, False),  # LB, LBU
                            0x11: (2, True), 0x15: (2, False),  # LH, LHU
                            0x13: (4, False)}                    # LW

                if op2 in store_ops:
                    sz = store_ops[op2]
                    if sz == 1:
                        val = uc.reg_read(self.gpr_map[ry_gpr]) & 0xFF
                    elif sz == 2:
                        val = uc.reg_read(self.gpr_map[ry_gpr]) & 0xFFFF
                    else:
                        val = uc.reg_read(self.gpr_map[ry_gpr])

                    # Write the value to memory first
                    uc.mem_write(target, val.to_bytes(sz, 'little'))

                    # Invoke SPI register hook if targeting SPI controller
                    if is_spi_reg:
                        self._hook_spi_write(uc, UC_MEM_WRITE, target, sz, val, None)

                    # Invoke SPI flash write hook if targeting flash region
                    if is_flash_region:
                        self._hook_spi_flash_write(uc, UC_MEM_WRITE, target, sz, val, None)

                    # Handle UART writes
                    if sz == 1 and target == 0xb8018300:
                        self._uart_log(val)
                        self.mu.mem_write(0xb8018305, b'\x20')
                    elif sz == 4 and target <= 0xb8018300 < target + 4:
                        off = 0xb8018300 - target
                        self._uart_log((val >> (off * 8)) & 0xFF)

                elif op2 in load_ops:
                    sz, signed = load_ops[op2]

                    # Invoke SPI flash read hook if targeting flash region
                    # (handles both command mode responses and passthrough offset logging)
                    if is_flash_region:
                        self._hook_spi_flash_read(uc, UC_MEM_READ, target, sz, 0, None)

                    # Invoke SPI register read hook if targeting SPI regs
                    if is_spi_reg:
                        self._hook_spi_read(uc, UC_MEM_READ, target, sz, 0, None)

                    # Now read the (possibly updated) value from memory
                    data = uc.mem_read(target, sz)
                    if signed:
                        val = int.from_bytes(data, 'little', signed=True) & 0xFFFFFFFF
                    else:
                        val = int.from_bytes(data, 'little')
                    uc.reg_write(self.gpr_map[ry_gpr], val)
                else:
                    return

                uc.reg_write(UC_MIPS_REG_PC, address + 4)
                self._last_hook_size = 4
                self._last_hook_addr = address
                uc.emu_stop()
                return

            # ---- MIPS32 Instruction Handling ----
            insn = int.from_bytes(insn_bytes, byteorder='little')
            
            opcode = (insn >> 26) & 0x3F
            rs = (insn >> 21) & 0x1F
            rt = (insn >> 16) & 0x1F
            rd = (insn >> 11) & 0x1F
            imm = insn & 0xFFFF
            if imm & 0x8000: imm -= 0x10000 

            # MFC0: opcode=0x10 (COP0), rs=0x00 (MF)
            # Intercept reads of CP0 Count register (rd=9).
            # Unicorn doesn't increment CP0 Count, so firmware polling loops hang.
            # We set the dest register to our simulated cp0_count, advance PC,
            # and stop emulation so Unicorn doesn't overwrite with its stale value.
            if opcode == 0x10 and rs == 0x00 and rd == 9:
                uc.reg_write(self.gpr_map[rt], self.cp0_count)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)
                # Update tracking BEFORE emu_stop — _hook_code may not fire
                # after emu_stop, so _detect_isa_mode needs these for re-entry.
                self._last_hook_size = 4
                self._last_hook_addr = address
                if self.is_mips16_addr(address + 4):
                    self.mips32_islands.add(address + 4)
                uc.emu_stop()
                return

            # LUI handled natively by Unicorn

            base = uc.reg_read(self.gpr_map[rs])
            target = base + imm
            
            # Check MMIO
            is_mmio = False
            if (0x18000000 <= target < 0x19000000) or \
               (0x98000000 <= target < 0x99000000) or \
               (0xB8000000 <= target < 0xB9000000):
                is_mmio = True
                
            # FORCE MANUAL EMULATION FOR ALL STORES TO ENSURE SYNC
            if not is_mmio:
                return

            val = 0
            
            if opcode == 0x28: # SB
                val = uc.reg_read(self.gpr_map[rt]) & 0xFF
                val_bytes = val.to_bytes(1, byteorder='little')
                uc.mem_write(target, val_bytes)
                # If target is UART, hook will handle it via uc.mem_write
                if target == 0xb8018300:
                    self._uart_log(val)
                    self.mu.mem_write(0xb8018305, b'\x20') 
                uc.reg_write(UC_MIPS_REG_PC, address + 4)

            elif opcode == 0x29: # SH
                val = uc.reg_read(self.gpr_map[rt]) & 0xFFFF
                val_bytes = val.to_bytes(2, byteorder='little')
                uc.mem_write(target, val_bytes)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)

            elif opcode == 0x2B: # SW
                val = uc.reg_read(self.gpr_map[rt])
                val_bytes = val.to_bytes(4, byteorder='little')
                uc.mem_write(target, val_bytes)
                if target <= 0xb8018300 < target + 4:
                    offset = 0xb8018300 - target
                    byte_val = (val >> (offset * 8)) & 0xFF
                    self._uart_log(byte_val)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)
                
            elif opcode == 0x23: # LW
                data = uc.mem_read(target, 4)
                val = int.from_bytes(data, byteorder='little', signed=False)
                uc.reg_write(self.gpr_map[rt], val)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)

            elif opcode == 0x20: # LB
                data = uc.mem_read(target, 1)
                val = int.from_bytes(data, byteorder='little', signed=True)
                uc.reg_write(self.gpr_map[rt], val)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)

            elif opcode == 0x24: # LBU
                data = uc.mem_read(target, 1)
                val = int.from_bytes(data, byteorder='little', signed=False)
                uc.reg_write(self.gpr_map[rt], val)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)
                
            elif opcode == 0x21: # LH
                data = uc.mem_read(target, 2)
                val = int.from_bytes(data, byteorder='little', signed=True)
                uc.reg_write(self.gpr_map[rt], val)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)

            elif opcode == 0x25: # LHU
                data = uc.mem_read(target, 2)
                val = int.from_bytes(data, byteorder='little', signed=False)
                uc.reg_write(self.gpr_map[rt], val)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)

        except Exception as e:
            # self.log(f"Error in manual instruction at {hex(address)}: {e}")
            pass

    # MIPS16 3-bit register encoding → MIPS32 register index
    MIPS16_REG_MAP = [16, 17, 2, 3, 4, 5, 6, 7]  # s0,s1,v0,v1,a0,a1,a2,a3

    def _emulate_mips16_manual(self, pc):
        """Manually emulate a MIPS16 instruction that Unicorn cannot execute.
        
        Returns True if the instruction was emulated and PC advanced,
        False if the instruction is not supported for manual emulation.
        """
        raw = self.mu.mem_read(pc, 4)
        insn = int.from_bytes(raw[0:2], byteorder='little')
        major_op = (insn >> 11) & 0x1F
        rx_idx = (insn >> 8) & 0x7
        ry_idx = (insn >> 5) & 0x7
        rx_gpr = self.MIPS16_REG_MAP[rx_idx]
        ry_gpr = self.MIPS16_REG_MAP[ry_idx]
        
        # SHIFT: SLL/SRL/SRA (opcode 00110 = 6)
        if major_op == 0x06:
            sa = (insn >> 2) & 0x7
            func = insn & 0x3
            if sa == 0:
                sa = 8
            ry_val = self.mu.reg_read(self.gpr_map[ry_gpr])
            if func == 0:  # SLL
                result = (ry_val << sa) & 0xFFFFFFFF
            elif func == 2:  # SRA
                # Sign-extend to 32 bits, then arithmetic shift right
                if ry_val & 0x80000000:
                    ry_val_s = ry_val - 0x100000000
                else:
                    ry_val_s = ry_val
                result = (ry_val_s >> sa) & 0xFFFFFFFF
            elif func == 3:  # SRL
                result = (ry_val >> sa) & 0xFFFFFFFF
            else:
                return False
            self.mu.reg_write(self.gpr_map[rx_gpr], result)
            self.mu.reg_write(UC_MIPS_REG_PC, pc + 2)
            return True
        
        # CMPI (opcode 01110 = 0x0E): compare rx with immediate, result in T8
        if major_op == 0x0E:
            imm = insn & 0xFF
            rx_val = self.mu.reg_read(self.gpr_map[rx_gpr])
            # CMPI: T8 = (rx ^ imm)  — actually CMPI does: T8 = rx XOR imm
            # No wait — CMPI sets T8 = 1 if rx != imm, T8 = 0 if rx == imm
            # Actually in MIPS16, CMPI rx, imm sets T8 = (rx XOR imm)
            # The BTEQZ/BTNEZ branches test if T8 == 0 or T8 != 0
            result = rx_val ^ imm
            self.mu.reg_write(UC_MIPS_REG_T8, result & 0xFFFFFFFF)
            self.mu.reg_write(UC_MIPS_REG_PC, pc + 2)
            return True
        
        # SLTI (opcode 01010 = 0x0A): set T8 = (rx < imm) signed
        if major_op == 0x0A:
            imm = insn & 0xFF
            rx_val = self.mu.reg_read(self.gpr_map[rx_gpr])
            # Sign-extend both
            if rx_val & 0x80000000:
                rx_signed = rx_val - 0x100000000
            else:
                rx_signed = rx_val
            result = 1 if rx_signed < imm else 0
            self.mu.reg_write(UC_MIPS_REG_T8, result)
            self.mu.reg_write(UC_MIPS_REG_PC, pc + 2)
            return True
        
        # SLTIU (opcode 01011 = 0x0B): set T8 = (rx < imm) unsigned
        if major_op == 0x0B:
            imm = insn & 0xFF
            rx_val = self.mu.reg_read(self.gpr_map[rx_gpr])
            result = 1 if rx_val < imm else 0
            self.mu.reg_write(UC_MIPS_REG_T8, result)
            self.mu.reg_write(UC_MIPS_REG_PC, pc + 2)
            return True
        
        # ADDIU (opcode 01000 = 0x08): rx = rx + sign_ext(imm8)
        if major_op == 0x08:
            imm = insn & 0xFF
            if imm & 0x80:
                imm -= 0x100
            rx_val = self.mu.reg_read(self.gpr_map[rx_gpr])
            result = (rx_val + imm) & 0xFFFFFFFF
            self.mu.reg_write(self.gpr_map[rx_gpr], result)
            self.mu.reg_write(UC_MIPS_REG_PC, pc + 2)
            return True
        
        # LI (opcode 01101 = 0x0D): rx = imm8
        if major_op == 0x0D:
            imm = insn & 0xFF
            self.mu.reg_write(self.gpr_map[rx_gpr], imm)
            self.mu.reg_write(UC_MIPS_REG_PC, pc + 2)
            return True
        
        # RR format (opcode 11101 = 0x1D): register-register operations
        # Uses 5-bit function code in bits[4:0].
        # Some instructions (ADDU func=0x01) also use rz from bits[4:2],
        # but the func5 value uniquely identifies the instruction.
        if major_op == 0x1D:
            func5 = insn & 0x1F
            rz_idx = (insn >> 2) & 0x7
            rz_gpr = self.MIPS16_REG_MAP[rz_idx]
            rx_val = self.mu.reg_read(self.gpr_map[rx_gpr])
            ry_val = self.mu.reg_read(self.gpr_map[ry_gpr])
            
            # ADDU: func5=0x01, rz = rx + ry (RRR 3-register format)
            if func5 == 0x01:
                result = (rx_val + ry_val) & 0xFFFFFFFF
                self.mu.reg_write(self.gpr_map[rz_gpr], result)
            # SLTU: func5=0x03, T8 = (rx < ry) ? 1 : 0 (unsigned)
            # Result goes to T8 for use with BTEQZ/BTNEZ conditional branches.
            elif func5 == 0x03:
                self.mu.reg_write(UC_MIPS_REG_T8, 1 if rx_val < ry_val else 0)
            # CMP: func5=0x0A, T8 = rx XOR ry
            elif func5 == 0x0A:
                self.mu.reg_write(UC_MIPS_REG_T8, (rx_val ^ ry_val) & 0xFFFFFFFF)
            # NEG: func5=0x0B, rx = -ry
            elif func5 == 0x0B:
                self.mu.reg_write(self.gpr_map[rx_gpr], (-ry_val) & 0xFFFFFFFF)
            # AND: func5=0x0C
            elif func5 == 0x0C:
                self.mu.reg_write(self.gpr_map[rx_gpr], rx_val & ry_val)
            # OR: func5=0x0D
            elif func5 == 0x0D:
                self.mu.reg_write(self.gpr_map[rx_gpr], rx_val | ry_val)
            # XOR: func5=0x0E
            elif func5 == 0x0E:
                self.mu.reg_write(self.gpr_map[rx_gpr], rx_val ^ ry_val)
            # NOT: func5=0x0F
            elif func5 == 0x0F:
                self.mu.reg_write(self.gpr_map[rx_gpr], (~ry_val) & 0xFFFFFFFF)
            else:
                return False
            
            self.mu.reg_write(UC_MIPS_REG_PC, pc + 2)
            return True
        
        return False

    def apply_manual_fixes(self):
        """No-op: kept for API compatibility with test scripts"""
        pass

    def invalidate_jit(self, address):
        """No-op: kept for API compatibility with test scripts"""
        pass

    def is_mips16_addr(self, address):
        """Heuristic to check if address is in known MIPS16 region"""
        # Main firmware body seems to be below 0x81E8E000
        # Loader/Trigger at 0x81E8E1B8 is MIPS32
        if (address & 0xFFE00000) == 0x81E00000:
             if address < 0x81E8E000:
                 return True
        return False

    def _detect_isa_mode(self, pc):
        """Determine ISA mode by checking learned MIPS32 islands then opcode heuristics.
        
        Strategy:
        1. Outside MIPS16 range → always MIPS32
        2. PC in mips32_islands (seen executing as MIPS32 before) → MIPS32
        3. Nearby addresses in mips32_islands → likely MIPS32 (mid-function re-entry)
        4. Probe 4 bytes at PC: if the opcode field matches a valid MIPS32 primary
           opcode, AND the instruction passes structural checks → MIPS32
        5. Default → MIPS16
        """
        # 1. Outside MIPS16 range → MIPS32
        if not self.is_mips16_addr(pc):
            return ISAMode.MIPS32
        
        # 1b. MIPS32 requires 4-byte alignment. If we're in the MIPS16 range
        # and PC is NOT 4-byte aligned, it cannot be MIPS32.
        if pc & 0x3:
            return ISAMode.MIPS16
        
        # 2. Exact match in learned set
        if pc in self.mips32_islands:
            return ISAMode.MIPS32
        
        # 3. Nearby addresses — if we stopped mid-function, adjacent instructions
        #    were seen as MIPS32 (4-byte aligned)
        for offset in range(4, 20, 4):
            if (pc + offset) in self.mips32_islands or (pc - offset) in self.mips32_islands:
                return ISAMode.MIPS32
        
        # Rule 3b (last_hook_size == 4) REMOVED: caused false MIPS32 detection
        # at MIPS16 addresses when batch boundaries fell after MIPS32 code.
        # The mips32_islands set (rules 2 and 3) handles this correctly.
        
        # 4. Conservative byte-probing for first encounters
        # Only match very specific MIPS32 patterns that cannot be MIPS16.
        # The broad opcode check was removed because MIPS16 byte pairs frequently
        # have opcode6 values that collide with valid MIPS32 opcodes.
        try:
            raw = self.mu.mem_read(pc, 4)
            word32 = int.from_bytes(raw, byteorder='little')
            
            # Don't check NOP (0x00000000) — zero-filled memory matches it and
            # would falsely classify uninitialized MIPS16-range addresses as MIPS32.
            # Real MIPS32 NOPs within functions are covered by mips32_islands
            # (adjacent instructions would have been recorded).
            
            # JR $RA (0x03E00008) — unique 4-byte pattern
            if word32 == 0x03E00008:
                return ISAMode.MIPS32
            
            opcode6 = (word32 >> 26) & 0x3F
            
            # LUI with hardware-address immediates (0xB800, 0xAFC0, etc.)
            # LUI opcode=0x0F, format: LUI rt, imm16
            # These are function prologues for MIPS32 functions that access MMIO.
            if opcode6 == 0x0F:
                imm16 = word32 & 0xFFFF
                if imm16 in (0xB800, 0xB802, 0xAFC0, 0x8000, 0xA000):
                    return ISAMode.MIPS32
            
            # MFC0 / MTC0 (opcode=0x10, rs=0x00 or 0x04)
            # These are unique to MIPS32 coprocessor instructions
            if opcode6 == 0x10:
                rs = (word32 >> 21) & 0x1F
                if rs in (0x00, 0x04):  # MFC0, MTC0
                    return ISAMode.MIPS32
        except Exception:
            pass
        
        # 5. Default: trust the address-based heuristic
        return ISAMode.MIPS16

    def run(self, max_instructions=None):
        cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
        self.log(f"Starting emulation at {hex(cur_pc)}...")
        
        if max_instructions is not None:
            self.max_instructions = max_instructions
        
        end_addr = self.base_addr + self.rom_size
        
        try:
            while cur_pc < end_addr:

                
                # Check for max instruction count stop
                if self.max_instructions and self.instruction_count >= self.max_instructions:
                    break
                
                # MIPS16 Mode Force
                start_pc = cur_pc
                
                # If we are currently AT a breakpoint/stop address, we must step over it
                # to avoid hitting it immediately in emu_start.
                if cur_pc in self.breakpoints or (self.stop_instr is not None and cur_pc == self.stop_instr):
                    # self.log(f"[DEBUG] Stepping over breakpoint at 0x{cur_pc:08X}")
                    self.step()
                    cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
                    if self.max_instructions and self.instruction_count >= self.max_instructions:
                        break
                    if cur_pc >= end_addr or (cur_pc & ~1) == 0:
                        break
                    start_pc = cur_pc

                # Determine ISA mode for emu_start by probing the bytes at PC.
                if self._detect_isa_mode(start_pc) == ISAMode.MIPS16:
                    start_pc |= 1
                    self.isa_mode = ISAMode.MIPS16
                else:
                    self.isa_mode = ISAMode.MIPS32

                # Run!
                self._emu_started_as_mips32 = (self.isa_mode == ISAMode.MIPS32)
                prev_pc = cur_pc
                self.mu.emu_start(start_pc, end_addr)
                
                # If we stopped, update PC
                cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
                
                # Stuck-PC detection: if Unicorn returned to the same PC,
                # it failed to execute the instruction. For MIPS16 code this
                # typically means the instruction type is unsupported by Unicorn.
                # Try manual emulation before giving up.
                if cur_pc == prev_pc and self.isa_mode == ISAMode.MIPS16:
                    if self._emulate_mips16_manual(cur_pc):
                        cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
                    # else: leave cur_pc as-is, will re-enter loop and detect
                    #        via max_instructions or other stop condition
                
                # If we hit a breakpoint or stop address, break the loop to return to caller
                if cur_pc in self.breakpoints or (self.stop_instr is not None and cur_pc == self.stop_instr):
                    break
                    
                # Stop if PC is NULL
                if (cur_pc & ~1) == 0:
                    self.log("[!] Stopped: Jump to NULL")
                    break
        
        except UcError as e:
            self.log(f"Unicorn Error: {e}")
            self.log(f"PC at error: {hex(self.mu.reg_read(UC_MIPS_REG_PC))}")
            self.log(f"Status at error: {hex(self.mu.reg_read(UC_MIPS_REG_CP0_STATUS))}")
            raise  # Re-raise so GUI can break
        except Exception as e:
            import traceback
            self.log(f"Error: {e}")
            self.log(traceback.format_exc())
            raise  # Re-raise so GUI can break

    def runStep(self):
        cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
        end_addr = self.base_addr + self.rom_size
        
        try:

              
             # MIPS16 Fix: If in MIPS16 region, force Thumb/MIPS16 mode by setting LSB
             start_pc = cur_pc
             if self.is_mips16_addr(start_pc):
                 start_pc |= 1
                 
             # Run 1 instruction
             self.is_stepping = True
             try:
                 self.mu.emu_start(start_pc, end_addr, count=1)
             finally:
                 self.is_stepping = False
             
             # Stop if PC is NULL
             new_pc = self.mu.reg_read(UC_MIPS_REG_PC)
             if (new_pc & ~1) == 0:
                 self.log("[!] Stopped: Jump to NULL")
             
        except UcError as e:
            self.log(f"Unicorn Error: {e}")
            self.log(f"PC at error: {hex(self.mu.reg_read(UC_MIPS_REG_PC))}")
            raise  # Re-raise so GUI can break
        except Exception as e:
            self.log(f"Error: {e}")
            raise  # Re-raise so GUI can break
    
    # NEW: Unified Stepping APIs
    
    def step(self) -> StepResult:
        """
        Execute one instruction in the current ISA mode
        
        Returns:
            StepResult with execution details
        """
        pc = self.mu.reg_read(UC_MIPS_REG_PC)
        mode_before = self.isa_mode.value
        
        # ISA mode switching in step() relies on:
        # 1. JALX detection in _step_mips16/_step_mips32 (switches mode on JALX)
        # 2. run() setting self.isa_mode = MIPS16 when entering MIPS16 region
        # We do NOT use is_mips16_addr() here because MIPS32 functions exist
        # within the MIPS16 address range (e.g., 0x81E8CE14 called via jal).

        # DEBUG: Log current mode (only if debug enabled)
        if self.debug_enabled:
            self.log(f"[DEBUG] step() at PC=0x{pc:08X}, mode={self.isa_mode.value}")
        
        self._step_count = 0  # Reset for hook-based single-stepping
        self.is_stepping = True
        try:
            if self.isa_mode == ISAMode.MIPS16:
                result = self._step_mips16(pc)
            else:
                result = self._step_mips32(pc)
        finally:
            self.is_stepping = False
        
        # Detect and stop on jump to NULL (0x0)
        # We check result.next_pc & ~1 because MIPS16 targets might have LSB set
        if (result.next_pc & ~1) == 0:
            self.log(f"\n[!] STOPPED: Program is about to jump to 0x0 from 0x{pc:08X}")
            self.log(f"    Instruction: {result.instruction} {result.operands}")
            # Raise exception to stop continuous execution if running
            raise Exception(f"Jump to NULL (0x0) detected at 0x{pc:08X}: {result.instruction} {result.operands}")
        
        # Update mode if switched
        if result.mode_switched:
            self.isa_mode = ISAMode.MIPS32 if result.mode_after == 'mips32' else ISAMode.MIPS16
            
            # Enable debug logging when entering MIPS16 for first time
            if result.mode_after == 'mips16' and not self.debug_enabled:
                self.debug_enabled = True
                self.log("[DEBUG] MIPS16 mode entered - enabling debug logging")
            
            if self.debug_enabled:
                self.log(f"[DEBUG] Mode switched: {result.mode_before} -> {result.mode_after}")
        
        # Update instruction counter
        self.instruction_count += 1
        
        # Track call stack for step_out
        if result.is_call:
            self.call_stack.append(result.address)
        elif result.is_return and self.call_stack:
            self.call_stack.pop()
        
        return result
    
    def step_into(self) -> StepResult:
        """
        Step into function calls (same as step())
        
        Returns:
            StepResult with execution details
        """
        return self.step()
    
    def step_over(self) -> StepResult:
        """
        Step over function calls (execute entire function if next instruction is a call)
        
        Returns:
            StepResult with execution details
        """
        # Execute one step
        result = self.step()
        
        # If it's a call, keep executing until we return
        if result.is_call:
            return_address = result.next_pc
            max_steps = 100000  # Safety limit
            steps = 0
            
            while steps < max_steps:
                current_pc = self.mu.reg_read(UC_MIPS_REG_PC)
                if current_pc == return_address:
                    # We've returned from the call
                    break
                
                step_result = self.step()
                steps += 1
                
                # If we hit a breakpoint or stop condition, return immediately
                if self.stop_instr and current_pc == self.stop_instr:
                    break
        
        return result
    
    def step_out(self) -> StepResult:
        """
        Step out of current function (execute until return)
        
        Returns:
            StepResult with execution details
        """
        initial_stack_depth = len(self.call_stack)
        max_steps = 100000  # Safety limit
        steps = 0
        last_result = None
        
        while steps < max_steps:
            last_result = self.step()
            steps += 1
            
            # Check if we've returned from the function
            if len(self.call_stack) < initial_stack_depth:
                break
            
            # If we hit a stop condition, break
            current_pc = self.mu.reg_read(UC_MIPS_REG_PC)
            if self.stop_instr and current_pc == self.stop_instr:
                break
        
        return last_result if last_result else StepResult(
            address=self.mu.reg_read(UC_MIPS_REG_PC),
            instruction="???",
            operands="",
            next_pc=self.mu.reg_read(UC_MIPS_REG_PC),
            mode_before=self.isa_mode.value,
            mode_after=self.isa_mode.value
        )
    
    def _step_mips32(self, pc: int) -> StepResult:
        """Execute one MIPS32 instruction using Unicorn"""
        mode_before = 'mips32'
        
        # Read instruction
        insn_bytes = self.mu.mem_read(pc, 4)
        
        # Decode for display
        mnemonic = "???"
        operands = ""
        try:
            disasm = list(self.md.disasm(insn_bytes, pc))
            if disasm:
                mnemonic = disasm[0].mnemonic
                operands = disasm[0].op_str
        except:
            pass
        
        # DEBUG: Log JALX instructions (only if debug enabled)
        if mnemonic == 'jalx' and self.debug_enabled:
            self.log(f"[DEBUG] Executing JALX at 0x{pc:08X} -> target {operands}")
        
        # Execute one instruction with Unicorn
        end_addr = self.base_addr + self.rom_size
        try:

            self.mu.emu_start(pc, end_addr, count=1)
        except Exception as e:
            pass  # Continue even on error
        
        next_pc = self.mu.reg_read(UC_MIPS_REG_PC)
        
        # DEBUG: Log PC after JALX (only if debug enabled)
        if mnemonic == 'jalx' and self.debug_enabled:
            self.log(f"[DEBUG] After JALX: PC = 0x{next_pc:08X}, switching to MIPS16 mode")
        
        # Check for mode switch (JALX instruction)
        mode_after = mode_before
        mode_switched = False
        if mnemonic == 'jalx':
            mode_after = 'mips16'
            mode_switched = True
        elif mnemonic == 'jr' and 'ra' in operands:
            # jr $ra: if RA had bit 0 set, returning to MIPS16 code.
            # JALX sets RA with bit 0 to mark the return as MIPS16.
            # Check RA AFTER the jr executes (Unicorn already jumped).
            # We need the RA value before jr cleared it - but Unicorn's jr
            # uses the register value at execution time. RA still has the
            # original value since jr doesn't modify RA.
            ra_val = self.mu.reg_read(UC_MIPS_REG_RA)
            if ra_val & 1:
                mode_after = 'mips16'
                mode_switched = True
        
        # Determine instruction type
        is_call = mnemonic in ['jal', 'jalr', 'jalx']
        is_return = mnemonic in ['jr'] and 'ra' in operands
        is_branch = mnemonic.startswith('b') or mnemonic.startswith('j')
        
        return StepResult(
            address=pc,
            instruction=mnemonic,
            operands=operands,
            next_pc=next_pc,
            mode_before=mode_before,
            mode_after=mode_after,
            is_branch=is_branch,
            is_call=is_call,
            is_return=is_return,
            mode_switched=mode_switched,
            instruction_size=4
        )
    
    def _step_mips16(self, pc: int) -> StepResult:
        """Execute one MIPS16 instruction using Unicorn native engine"""
        mode_before = 'mips16'
        
        # Read instruction bytes for decode/display
        insn_bytes = self.mu.mem_read(pc, 2)
        mnemonic, operands = MIPS16Decoder.decode(insn_bytes, pc)
        
        # Determine instruction size (some MIPS16 are 4 bytes)
        # Check if it's an extended instruction (4-byte)
        first_word = int.from_bytes(insn_bytes, byteorder='little')
        opcode5 = (first_word >> 11) & 0x1F
        # Extended instructions have opcode 0b11110 (30) or JAL/JALX 0b00011 (3)
        if opcode5 == 30 or opcode5 == 3:
            insn_bytes = self.mu.mem_read(pc, 4)
            mnemonic, operands = MIPS16Decoder.decode(insn_bytes, pc)
            instruction_size = 4
        else:
            instruction_size = 2
        
        # Execute one instruction with Unicorn (LSB=1 for MIPS16 mode)
        end_addr = self.base_addr + self.rom_size
        try:
            self.mu.emu_start(pc | 1, end_addr, count=1)
        except Exception as e:
            pass  # Continue even on error
        
        next_pc = self.mu.reg_read(UC_MIPS_REG_PC)
        
        # If PC didn't advance, Unicorn failed to execute this MIPS16 instruction.
        # Fall back to manual emulation.
        if next_pc == pc:
            if self._emulate_mips16_manual(pc):
                next_pc = self.mu.reg_read(UC_MIPS_REG_PC)
        
        # Detect mode switch (jalx switches back to MIPS32)
        mode_after = mode_before
        mode_switched = False
        if mnemonic == 'jalx':
            mode_after = 'mips32'
            mode_switched = True
        elif mnemonic in ['jrc', 'jr'] and 'ra' in operands:
            # Return from MIPS16 subroutine — check if target is MIPS32
            if not self.is_mips16_addr(next_pc):
                mode_after = 'mips32'
                mode_switched = True
        
        # Determine instruction type
        is_call = mnemonic in ['jal', 'jalr', 'jalx']
        is_return = mnemonic in ['jr', 'jrc'] and 'ra' in operands
        is_branch = mnemonic.startswith('b') or mnemonic.startswith('j')
        
        return StepResult(
            address=pc,
            instruction=mnemonic,
            operands=operands,
            next_pc=next_pc,
            mode_before=mode_before,
            mode_after=mode_after,
            is_branch=is_branch,
            is_call=is_call,
            is_return=is_return,
            mode_switched=mode_switched,
            instruction_size=instruction_size
        )

    def skipInstruction(self):
        """Skip the current instruction by advancing PC by 4"""
        try:
            cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
            # Try to determine size of instruction at PC
            # Default to 4
            incr = 4
            try:
                code = self.mu.mem_read(cur_pc, 4)
                # We need a disassembler that understands the current mode...
                # Sim's self.md is MIPS32. If we are in MIPS16, we might fail or get it wrong.
                # Heuristic: Check PC alignment? MIPS16 PC is usually odd in JALX but even in execution?
                # Actually, in Unicorn, PC is the address.
                # If we are in MIPS16 mode, we might need a separate disassembler.
                for i in self.md.disasm(code, cur_pc):
                    incr = i.size
                    break
            except: pass

            self.mu.reg_write(UC_MIPS_REG_PC, cur_pc + incr)
            self.log(f"Skipped instruction at 0x{cur_pc:08X} (size {incr})")
        except Exception as e:
            self.log(f"Error skipping instruction: {e}")

    def get_instructions_around_pc(self, pc, before=10, after=10, forced_mips16_addresses=None, breakpoints=None):
        if not self.mu: return []
        instructions = []
        forced_mips16_addresses = forced_mips16_addresses or set()
        breakpoints = breakpoints or {}
        
        # Backward scan (Tricky with variable length)
        # Strategy: Go back 'before * 4' bytes (approx), then disassemble forward.
        # If we desync at PC, adjust start point.
        
        start_attempts = [pc - (before * 4), pc - (before * 4) + 2]
        best_instrs = []
        
        for start_addr in start_attempts:
            if start_addr < 0: continue
            
            # Check if PC is a JALX target before scanning
            pc_is_jalx_target = False
            prev_exec = getattr(self, 'prev_executed_pc', None)
            if prev_exec:
                try:
                    prev_bytes = self.mu.mem_read(prev_exec, 4)
                    prev_disasm = list(self.md.disasm(prev_bytes, prev_exec))
                    if prev_disasm and prev_disasm[0].mnemonic == 'jalx':
                        pc_is_jalx_target = True
                        print(f"[DEBUG] PC 0x{pc:08X} is JALX target from 0x{prev_exec:08X}")
                except: pass
            
            temp_instrs = []
            curr = start_addr
            valid_sequence = False
            
            # Track if we're in a MIPS16 region (entered via JALX)
            in_mips16_region = False
            
            # Limit scan to reasonable amount to avoid infinite loops if something is wrong
            while curr <= pc + (after * 4): 
                # Decode one
                try:
                    # Check known size or Forced MIPS16
                    is_mips16 = False
                    
                    # 1. Execution History
                    known_size = self.instruction_sizes.get(curr)
                    if known_size == 2:
                        is_mips16 = True
                        # print(f"[DEBUG] 0x{curr:08X} is MIPS16 from execution history")
                    
                    # 2. Forced Address (Manual Toggle)
                    if curr in forced_mips16_addresses:
                        is_mips16 = True
                        # print(f"[DEBUG] 0x{curr:08X} is MIPS16 from forced addresses")
                    
                    # 3. JALX target detection
                    if not is_mips16 and curr == pc and pc_is_jalx_target:
                        is_mips16 = True
                        in_mips16_region = True  # Enter MIPS16 region
                        print(f"[DEBUG] 0x{curr:08X} is MIPS16 as JALX target - entering MIPS16 region")
                    
                    # 4. If we're in a MIPS16 region (and no execution history says otherwise), assume MIPS16
                    if not is_mips16 and in_mips16_region and known_size != 4:
                        is_mips16 = True
                        # print(f"[DEBUG] 0x{curr:08X} is MIPS16 from region continuation")

                    # 5. Check Simulator Heuristic (New)
                    if not is_mips16 and self.is_mips16_addr(curr):
                        is_mips16 = True
                        in_mips16_region = True

                    if is_mips16:
                        # It's MIPS16! Decode it properly
                        # Read first 2 bytes to check instruction type
                        first_word = self.mu.mem_read(curr, 2)
                        word1 = int.from_bytes(first_word, byteorder='little')
                        major_op = (word1 >> 11) & 0x1F
                        is_4byte = (major_op == 0x03 or major_op == 0x1E)  # JAL/JALX opcode or EXTEND
                        
                        # Read appropriate number of bytes
                        if is_4byte:
                            valid_bytes = self.mu.mem_read(curr, 4)
                            instr_size = 4
                        else:
                            valid_bytes = first_word
                            instr_size = 2
                        
                        # Decode MIPS16 instruction (with address for JAL target calculation)
                        mnemonic, operands = MIPS16Decoder.decode(valid_bytes, curr)
                        bytes_str = ' '.join(f'{b:02x}' for b in valid_bytes)
                        
                        temp_instrs.append({
                            'address': curr,
                            'bytes': bytes_str,
                            'mnemonic': mnemonic,
                            'operands': operands,
                            'loop_count': self.visit_counts.get(curr, 0),
                            'is_current': (curr == pc),
                            'is_breakpoint': (curr in breakpoints)
                        })
                        curr += instr_size
                        if curr == pc: valid_sequence = True
                        if curr > pc and not valid_sequence: break
                        if valid_sequence:
                             # check after count
                             count_after = sum(1 for i in temp_instrs if i['address'] > pc)
                             if count_after >= after: break
                        continue

                    # Try to disassemble as MIPS32 first
                    code = self.mu.mem_read(curr, 4)
                    disasm = list(self.md.disasm(code, curr))
                    
                    if not disasm:
                        # Fallback: treat as MIPS16 instruction
                        try:
                            # Read first 2 bytes to check instruction type
                            first_word = self.mu.mem_read(curr, 2)
                            word1 = int.from_bytes(first_word, 'little')
                            major_op = (word1 >> 11) & 0x1F
                            is_4byte = (major_op == 0x03 or major_op == 0x1E)
                            
                            # Read appropriate number of bytes
                            if is_4byte:
                                valid_bytes = self.mu.mem_read(curr, 4)
                                instr_size = 4
                            else:
                                valid_bytes = first_word
                                instr_size = 2
                            
                            mnemonic, operands = MIPS16Decoder.decode(valid_bytes, curr)
                            bytes_str = ' '.join(f'{b:02x}' for b in valid_bytes)
                            
                            temp_instrs.append({
                                'address': curr,
                                'bytes': bytes_str,
                                'mnemonic': mnemonic,
                                'operands': operands,
                                'loop_count': self.visit_counts.get(curr, 0),
                                'is_current': (curr == pc),
                                'is_breakpoint': (curr in breakpoints)
                            })
                            curr += instr_size
                        except:
                            curr += 4  # Skip if read fails
                        continue
                        
                    instr = disasm[0]
                    
                    item = {
                        'address': curr,
                        'bytes': ' '.join(f'{b:02x}' for b in instr.bytes),
                        'mnemonic': instr.mnemonic,
                        'operands': instr.op_str,
                        'loop_count': self.visit_counts.get(curr, 0),
                        'is_current': (curr == pc),
                        'is_breakpoint': (curr in breakpoints)
                    }
                    temp_instrs.append(item)
                    
                    if curr == pc:
                        valid_sequence = True
                        
                    curr += instr.size
                    
                    # If we passed PC
                    if curr > pc and not valid_sequence:
                         break # Desync
                         
                    # Stop if we have enough "after" instructions
                    if valid_sequence:
                        # Count how many after PC
                        count_after = 0
                        for i in reversed(temp_instrs):
                            if i['address'] > pc: count_after += 1
                            else: break
                        if count_after >= after: break
                        
                except:
                    curr += 4 # Fallback
            
            if valid_sequence:
                best_instrs = temp_instrs
                break
        
        if not best_instrs:
            # Ultimate fallback: Show raw hex dump around PC (suppress repeated prints)
            if not hasattr(self, '_last_fallback_pc') or self._last_fallback_pc != pc:
                print(f"[DEBUG] No valid disassembly found, using hex dump fallback at PC=0x{pc:08X}")
                self._last_fallback_pc = pc
            curr = max(0, pc - 20)  # Show a bit before PC
            for i in range(25):  # Show ~50 bytes
                try:
                    # Read first 2 bytes to check instruction type
                    first_word = self.mu.mem_read(curr, 2)
                    word1 = int.from_bytes(first_word, byteorder='little')
                    major_op = (word1 >> 11) & 0x1F
                    is_4byte = (major_op == 0x03 or major_op == 0x1E)
                    
                    # Read appropriate number of bytes
                    if is_4byte:
                        code = self.mu.mem_read(curr, 4)
                        instr_size = 4
                    else:
                        code = first_word
                        instr_size = 2
                    
                    mnemonic, operands = MIPS16Decoder.decode(code, curr)
                    bytes_str = ' '.join(f'{b:02x}' for b in code)
                    
                    best_instrs.append({
                        'address': curr,
                        'bytes': bytes_str,
                        'mnemonic': mnemonic,
                        'operands': operands,
                        'loop_count': self.visit_counts.get(curr, 0),
                        'is_current': (curr == pc),
                        'is_breakpoint': (curr in breakpoints)
                    })
                    curr += instr_size
                except:
                    curr += 2
                 
        # Filter to requested window
        # Find index of PC
        pc_idx = -1
        for i, item in enumerate(best_instrs):
            if item['address'] == pc: 
                pc_idx = i
                break
                
        if pc_idx != -1:
            start_idx = max(0, pc_idx - before)
            end_idx = min(len(best_instrs), pc_idx + after + 1)
            instructions = best_instrs[start_idx:end_idx]
        else:
            instructions = best_instrs[:before+after] # Fallback
            
        return instructions


