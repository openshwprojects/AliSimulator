import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from unicorn import *
from unicorn.mips_const import *
from capstone import *
import json
import os
import sys
import threading
import time
import chips
import dump_catalog
from simulator import AliMipsSimulator, DUMPS_DIR, flash_size_for, resolve_dump
from mips16_decoder import MIPS16Decoder

FAMILIES = list(chips.FAMILY_CHOICES)
SIDECAR_AUTO = dump_catalog.SIDECAR_AUTO
SIDECAR_NONE = dump_catalog.SIDECAR_NONE

_REG_MAP = {
    "zero": UC_MIPS_REG_ZERO, "at": UC_MIPS_REG_AT, "v0": UC_MIPS_REG_V0, "v1": UC_MIPS_REG_V1,
    "a0": UC_MIPS_REG_A0, "a1": UC_MIPS_REG_A1, "a2": UC_MIPS_REG_A2, "a3": UC_MIPS_REG_A3,
    "t0": UC_MIPS_REG_T0, "t1": UC_MIPS_REG_T1, "t2": UC_MIPS_REG_T2, "t3": UC_MIPS_REG_T3,
    "t4": UC_MIPS_REG_T4, "t5": UC_MIPS_REG_T5, "t6": UC_MIPS_REG_T6, "t7": UC_MIPS_REG_T7,
    "s0": UC_MIPS_REG_S0, "s1": UC_MIPS_REG_S1, "s2": UC_MIPS_REG_S2, "s3": UC_MIPS_REG_S3,
    "s4": UC_MIPS_REG_S4, "s5": UC_MIPS_REG_S5, "s6": UC_MIPS_REG_S6, "s7": UC_MIPS_REG_S7,
    "t8": UC_MIPS_REG_T8, "t9": UC_MIPS_REG_T9, "k0": UC_MIPS_REG_K0, "k1": UC_MIPS_REG_K1,
    "gp": UC_MIPS_REG_GP, "sp": UC_MIPS_REG_SP, "fp": UC_MIPS_REG_FP, "ra": UC_MIPS_REG_RA,
    "PC": UC_MIPS_REG_PC, "HI": UC_MIPS_REG_HI, "LO": UC_MIPS_REG_LO,
}


class MIPSSimulatorGUI:
    def __init__(self, root, binary_file="dump.bin", family="Auto", json_path=None, fast_mode=False):
        self.root = root
        self.root.title("MIPS Simulator - GUI Debugger (New Engine)")
        self.root.geometry("1400x920")
        
        self._catalog = dump_catalog.catalog_entries()
        self._label_to_path = {label: path for label, path, _sc in self._catalog}
        self.BINARY_FILE = dump_catalog.resolve_catalog_dump(binary_file, self._catalog)
        self._sidecar_presets = dump_catalog.sidecar_presets(self._catalog)
        self._initial_family = family if family in FAMILIES else "Auto"
        self._initial_json = json_path if json_path else SIDECAR_AUTO
        self._initial_fast = bool(fast_mode)
        
        # Simulator instance
        self.sim = None
        
        # GUI state
        self.is_running = False
        self.paused = False
        self.execution_thread = None
        self.breakpoints = {}
        self.watches = []
        self.watch_previous_values = {}
        self.forced_mips16_addresses = set()
        self._prev_regs = {}
        self._log_buf = []
        self._uart_buf = []
        self._spi_buf = []
        
        # Temp breakpoints for stepping
        self.temp_breakpoints = set()

        # Load persistent data
        self.load_breakpoints()
        self.load_watches()
        
        # Create GUI
        self.create_gui()
        
        # Initialize Emulator
        self.init_emulator()

    def _step_over_breakpoint(self):
        """Helper to step exactly one instruction ignoring any breakpoint at current PC"""
        self.sim.runStep()
        
    def log(self, message):
        """Add message to log (buffered when running on the background execution thread)"""
        if self.is_running:
            self._log_buf.append(f"{message}\n")
            return
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)

    def on_uart_write(self, char):
        """Handle UART output (buffered when running on the background execution thread)"""
        if isinstance(char, int):
            char = chr(char & 0xFF)
        if char.isprintable() or char in ['\n', '\r', '\t']:
            if self.is_running:
                self._uart_buf.append(char)
            else:
                self.uart_text.insert(tk.END, char)
                self.uart_text.see(tk.END)

    def on_spi_log(self, message):
        """Handle SPI log output (buffered when running on the background execution thread)"""
        if self.is_running:
            self._spi_buf.append(message + "\n")
        else:
            self.spi_text.insert(tk.END, message + "\n")
            self.spi_text.see(tk.END)

    def _flush_text_buffers(self):
        if self._log_buf:
            chunk = "".join(self._log_buf[-500:])
            self._log_buf.clear()
            self.log_text.insert(tk.END, chunk)
            self.log_text.see(tk.END)
        if self._uart_buf:
            chunk = "".join(self._uart_buf)
            self._uart_buf.clear()
            self.uart_text.insert(tk.END, chunk)
            self.uart_text.see(tk.END)
        if self._spi_buf:
            chunk = "".join(self._spi_buf[-500:])
            self._spi_buf.clear()
            self.spi_text.insert(tk.END, chunk)
            self.spi_text.see(tk.END)

    def _copy_text(self, text_widget):
        """Copy all text from a Text widget to clipboard"""
        content = text_widget.get("1.0", tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(content)

    def _apply_sidecar_selection(self):
        dump_catalog.apply_sidecar_selection(self.BINARY_FILE, self.sidecar_var.get(), self._sidecar_presets)

    def _sync_dump_combo_display(self):
        self.dump_var.set(dump_catalog.catalog_label_for(self.BINARY_FILE, self._catalog))

    def browse_dump(self):
        initial = DUMPS_DIR if os.path.isdir(DUMPS_DIR) else "."
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Select Firmware Image (.bin / .abs)",
            initialdir=initial,
            filetypes=[("Firmware images", "*.bin *.abs *.rom"), ("All files", "*.*")],
        )
        if path:
            self.BINARY_FILE = path
            self._sync_dump_combo_display()
            self.reset_emulator()

    def browse_json(self):
        initial = DUMPS_DIR if os.path.isdir(DUMPS_DIR) else "."
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Select Sidecar JSON (.json)",
            initialdir=initial,
            filetypes=[("Sidecar JSON", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.sidecar_var.set(path)
            self.reset_emulator()

    def _on_dump_selected(self, _event=None):
        sel = self.dump_var.get().strip()
        self.BINARY_FILE = dump_catalog.resolve_catalog_dump(sel, self._catalog)
        self._sync_dump_combo_display()
        self.reset_emulator()

    def _on_fast_mode_toggled(self):
        if self.sim is not None:
            self.sim.hook_every_instruction = not self.fast_mode_var.get()
            mode = "Fast mode (selective CP0 hooks)" if self.fast_mode_var.get() else "Exact per-instruction mode"
            self.log(f"Switched execution mode: {mode}")

    def _on_spi_dump_toggled(self):
        if self.sim is not None:
            self.sim.setSPIDump(self.spi_dump_var.get())

    def init_emulator(self):
        """Initialize the simulator backend"""
        try:
            if self.sim is not None and getattr(self.sim, "_stopper", None) is not None:
                try:
                    self.sim._stopper.close()
                except Exception:
                    pass
            self._apply_sidecar_selection()
            fam_sel = self.family_var.get()
            chip_arg = None if fam_sel == "Auto" else fam_sel
            # Create simulator instance with matching flash size
            self.sim = AliMipsSimulator(rom_size=flash_size_for(self.BINARY_FILE), log_handler=self.log)
            self.sim.hook_every_instruction = not self.fast_mode_var.get()
            self.sim.setSPIDump(self.spi_dump_var.get())
            self.sim.setUartHandler(self.on_uart_write)
            self.sim.setSpiHandler(self.on_spi_log)
            
            # Load the binary and attach default tuner/demod/GPIO peripherals
            self.sim.loadFile(self.BINARY_FILE, chip=chip_arg)
            self.sim.attach_tuner()
            
            # Printf hook (Legacy support from old GUI)
            self.sim.mu.hook_add(UC_HOOK_CODE, self.hook_printf, begin=0xAFC00494, end=0xAFC00494)
            
            self._prev_regs.clear()
            chip_id = int.from_bytes(self.sim._mmio_view[2:4], "little")
            self.root.title(f"MIPS Simulator - {os.path.basename(self.BINARY_FILE)} [{self.sim.chip.name} 0x{chip_id:04X}]")
            # Initialize GUI displays
            self.update_ui_safe()
            self.log(f"Initialized {self.BINARY_FILE} as {self.sim.chip.name} (chip ID 0x{chip_id:04X}, ir:{self.sim.ir_coding})")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initialize simulator: {e}")
            
    def reset_emulator(self):
        """Reset the emulator"""
        if self.is_running:
            self.pause_execution()
        self.is_running = False
        self.paused = False
        self.temp_breakpoints.clear()
        self._log_buf.clear()
        self._uart_buf.clear()
        self._spi_buf.clear()
        self.uart_text.delete("1.0", tk.END)
        self.spi_text.delete("1.0", tk.END)
        self.init_emulator()

    def show_screen(self):
        """Show what the firmware's OSD displays now (the GMA display layer the
        graphics engine drew into RAM, see AliMipsSimulator.capture_screen) and
        save it as screen.png."""
        if not self.sim:
            return
        path = os.path.abspath("screen.png")
        try:
            self.sim.capture_screen(path)
        except Exception as e:
            messagebox.showerror("Screen", f"Capture failed: {e}")
            return
        win = tk.Toplevel(self.root)
        win.title(f"OSD screen - {path}")
        img = tk.PhotoImage(file=path)
        if img.width() > 960:
            img = img.subsample(2, 2)
        label = tk.Label(win, image=img)
        label.image = img            # keep a reference
        label.pack()
        self.log(f"Screen captured to {path}")

    # -------------------------------------------------------------------------
    # Hooks
    # -------------------------------------------------------------------------
    def hook_printf(self, uc, address, size, user_data):
        try:
            a0 = uc.reg_read(UC_MIPS_REG_A0)
            # Read string from memory (max 256 bytes)
            s = b''
            for i in range(256):
                b = uc.mem_read(a0 + i, 1)
                if b == b'\x00': break
                s += b
            # msg = s.decode('utf-8', errors='replace')
            # self.log(f"➜ Printf(0x{address:X}): \"{msg}\"")
        except: pass

    # -------------------------------------------------------------------------
    # Execution Control
    # -------------------------------------------------------------------------
    def execute_single_instruction(self):
        """Execute one instruction using the new stepping API"""
        try:
            pc = self.sim.mu.reg_read(UC_MIPS_REG_PC)
            self.sim.step()
            self.check_watches()
            # Update UI immediately for single step
            self.update_ui_safe()
            return True
        except Exception as e:
            import traceback
            self.log(f"Step error at PC=0x{pc:08X}: {e}")
            self.log(f"Traceback: {traceback.format_exc()}")
            return False

    def step_into(self, event=None):
        """F11: Step Into"""
        if self.is_running: return
        self.temp_breakpoints.clear()
        self.execute_single_instruction()

    def step_skip(self, event=None):
        """Step Skip: Just advance PC by 4 without executing"""
        if self.is_running: return
        self.sim.skipInstruction()
        self.update_ui_safe()

    def step_over(self, event=None):
        """F10: Step Over"""
        if self.is_running: return
        self.temp_breakpoints.clear()
        
        # Analyze current instruction in the CPU's current ISA mode
        try:
            pc = self.sim.mu.reg_read(UC_MIPS_REG_PC)
            m16 = self.sim.is_mips16_mode()
            mnemonic, operands, size = self.sim._decode_for_display(pc, m16)
            if mnemonic in ['jal', 'jalx', 'jalr', 'jalrc', 'bal']:
                if m16:
                    # MIPS16: return address is after the call and its delay slot
                    # (JALRC has no delay slot)
                    return_addr = pc + size
                    if mnemonic != 'jalrc':
                        return_addr += self.sim._decode_for_display(return_addr, True)[2]
                else:
                    return_addr = pc + 8
                self.log(f"Stepping over call at 0x{pc:08X} -> break at 0x{return_addr:08X}")
                self.temp_breakpoints.add(return_addr)
                self.run_to_breakpoint()
                return
        except: pass
        
        # Default: just step into
        self.step_into()

    def step_out(self, event=None):
        """Shift+F11: Step Out"""
        if self.is_running: return
        self.temp_breakpoints.clear()
        
        try:
            ra = self.sim.mu.reg_read(UC_MIPS_REG_RA)
            if ra == 0:
                self.log("Warning: RA is 0")
                return
            self.log(f"Stepping out -> break at RA=0x{ra:08X}")
            self.temp_breakpoints.add(ra)
            self.run_to_breakpoint()
        except: pass

    def run_to_breakpoint(self):
        """Run until a breakpoint is hit (helper for Step Over/Out)"""
        self.run_continuous(stop_at_temp=True)

    def run_continuous(self, stop_at_temp=False):
        """Run execution loop using sim.run() for native speed"""
        if self.is_running: return
        
        if not stop_at_temp:
            self.temp_breakpoints.clear()
            
        self.is_running = True
        self.paused = False
        
        def run_loop():
            try:
                # If currently on a breakpoint, step once to move off it
                current_pc = self.sim.mu.reg_read(UC_MIPS_REG_PC)
                if current_pc in self.breakpoints:
                     self._step_over_breakpoint()
                
                # Run in batches for UI responsiveness.
                # Sync GUI breakpoints to simulator so sim.run()'s internal loop
                # correctly stops (otherwise it re-enters emu_start after hook's emu_stop).
                last_ui = 0.0
                while self.is_running and not self.paused:
                    fast = bool(self.fast_mode_var.get())
                    self.sim.hook_every_instruction = not fast
                    batch = 500_000 if fast else 50_000
                    bps = set(self.breakpoints.keys()) | self.temp_breakpoints
                    self.sim.breakpoints = bps
                    if fast:
                        self.sim.run(max_instructions=self.sim.instruction_count + batch,
                                     max_vtime=self.sim._vtime() + 0.25)
                    else:
                        self.sim.max_instructions = self.sim.instruction_count + batch
                        self.sim.run()
                    self.sim.breakpoints = set()  # Clear after run
                    if self.sim._stop_reason == 'breakpoint':
                        self.is_running = False
                        self.paused = True
                    
                    # Check watches between batches
                    if self.check_watches():
                        self.is_running = False
                        self.paused = True
                        break
                    
                    # Throttle UI refreshes to at most 10 Hz while running continuously
                    now = time.perf_counter()
                    if now - last_ui >= 0.10:
                        last_ui = now
                        self.root.after(0, self.update_ui_safe)
                        
            except Exception as e:
                self._log_buf.append(f"Execution Error: {e}\n")
                self.paused = True
            finally:
                self.is_running = False
                self.root.after(0, self.update_ui_safe)
                
        self.execution_thread = threading.Thread(target=run_loop, daemon=True)
        self.execution_thread.start()

    def pause_execution(self):
        self.paused = True
        self.is_running = False
        self.sim.mu.emu_stop() # Force stop if running
        self.log("Paused")

    # -------------------------------------------------------------------------
    # UI Updates (Registers, Instructions, Watches)
    # -------------------------------------------------------------------------
    def update_ui_safe(self):
        self._flush_text_buffers()
        self.update_instruction_display()
        self.update_status()
        self.update_registers()
        # self.update_watch_list() # Keeps watches updated? Yes.

    def update_status(self):
        if not self.sim: return
        try:
            pc = self.sim.mu.reg_read(UC_MIPS_REG_PC)
            chip_id = int.from_bytes(self.sim._mmio_view[2:4], "little")
            mode = "FAST" if self.fast_mode_var.get() else "EXACT"
            status = (f"PC: 0x{pc:08X} | Insns: {self.sim.instruction_count:,} | "
                      f"Chip: {self.sim.chip.name} (0x{chip_id:04X}) | GE: {self.sim.ge_ops} | [{mode}]")
            if self.is_running: status += " | [RUNNING]"
            elif self.paused: status += " | [PAUSED]"
            else: status += " | [STOPPED]"
            self.status_label.config(text=status)
        except: pass

    def update_registers(self):
        if not self.sim: return
        try:
            prev = self._prev_regs
            for name, const in _REG_MAP.items():
                val = self.sim.mu.reg_read(const)
                if prev.get(name) == val:
                    continue
                prev[name] = val
                lbl = self.reg_labels.get(name)
                if lbl:
                    fg = "blue" if name in ("PC", "sp", "ra") else ("black" if val != 0 else "gray")
                    lbl.config(fg=fg, text=f"{name.upper()}: {val:08X}")
        except: pass

    def update_instruction_display(self):
        self.instr_text.delete(1.0, tk.END)
        try:
            pc = self.sim.mu.reg_read(UC_MIPS_REG_PC)
            instructions = self.sim.get_instructions_around_pc(
                pc, 
                before=15, 
                after=15, 
                forced_mips16_addresses=self.forced_mips16_addresses, 
                breakpoints=self.breakpoints
            )
            
            for instr in instructions:
                loop_str = f" [LOOP {instr['loop_count']}]" if instr['loop_count'] > 1 else ""
                line = f"0x{instr['address']:08X}: {instr['bytes']:<15} {instr['mnemonic']:<8} {instr['operands']:<20}{loop_str}"
                
                start_idx = self.instr_text.index(tk.END + "-1c")
                self.instr_text.insert(tk.END, line)
                end_idx = self.instr_text.index(tk.END + "-1c")
                
                if instr['is_current']: self.instr_text.tag_add("current", start_idx, end_idx)
                elif instr['is_breakpoint']: self.instr_text.tag_add("breakpoint", start_idx, end_idx)
                elif instr['address'] < pc: self.instr_text.tag_add("prev", start_idx, end_idx)
                else: self.instr_text.tag_add("next", start_idx, end_idx)
                
                if instr['loop_count'] > 1: self.instr_text.tag_add("loop", start_idx, end_idx)
                if instr['is_breakpoint']:
                    name = self.breakpoints.get(instr['address'])
                    if name and name != "User":
                        self.instr_text.insert(tk.END, f" [BP: {name}]")
                    else:
                        self.instr_text.insert(tk.END, " [BP]")
                
                self.instr_text.insert(tk.END, "\n")
                
            self.instr_text.see("1.0")
            for i, instr in enumerate(instructions):
                if instr['is_current']: 
                    self.instr_text.see(f"{i+1}.0")
                    break
        except: pass

    def check_watches(self):
        """Check memory watches"""
        triggered = False
        for i, watch in enumerate(self.watches):
            try:
                if watch['type'] == 'direct':
                    addr = watch['address']
                    length = watch['length']
                    current_value = self.sim.peek(addr, length)
                elif watch['type'] == 'pointer':
                    ptr_addr = watch['ptr_address']
                    offset = watch.get('offset', 0)
                    length = watch['length']
                    ptr_bytes = self.sim.peek(ptr_addr, 4)
                    ptr_value = int.from_bytes(ptr_bytes, byteorder='little')
                    addr = ptr_value + offset
                    current_value = self.sim.peek(addr, length)
                else: continue
                
                prev_value = self.watch_previous_values.get(i)
                if prev_value is not None and prev_value != current_value:
                    if len(prev_value) <= 8:
                        prev_int = int.from_bytes(prev_value, byteorder='little')
                        curr_int = int.from_bytes(current_value, byteorder='little')
                        self.log(f"Watch #{i} triggered at 0x{addr:08X}: 0x{prev_int:08X} -> 0x{curr_int:08X}")
                    else:
                        self.log(f"Watch #{i} triggered at 0x{addr:08X}")
                        
                    if watch.get('break_on_change', True): triggered = True
                
                self.watch_previous_values[i] = current_value
            except: pass
        return triggered

    # -------------------------------------------------------------------------
    # GUI Creation (Layout)
    # -------------------------------------------------------------------------
    def create_gui(self):
        # Main Layout
        main_paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
        main_paned.pack(fill=tk.BOTH, expand=True)
        
        left_frame = tk.Frame(main_paned)
        main_paned.add(left_frame, width=820)

        # Target Firmware & Chip Family Bar
        target_frame = tk.LabelFrame(left_frame, text="Firmware / Target", padx=6, pady=6)
        target_frame.pack(fill=tk.X, padx=5, pady=(5, 2))
        row1 = tk.Frame(target_frame)
        row1.pack(fill=tk.X, pady=(0, 4))
        tk.Label(row1, text="Dump:").pack(side=tk.LEFT)
        self.dump_var = tk.StringVar()
        self.dump_combo = ttk.Combobox(row1, textvariable=self.dump_var, width=48,
                                       values=[label for label, _p, _sc in self._catalog])
        self.dump_combo.pack(side=tk.LEFT, padx=4, fill=tk.X, expand=True)
        self.dump_combo.bind("<<ComboboxSelected>>", self._on_dump_selected)
        self.dump_combo.bind("<Return>", self._on_dump_selected)
        tk.Button(row1, text="Browse...", command=self.browse_dump, width=9).pack(side=tk.LEFT, padx=2)

        row2 = tk.Frame(target_frame)
        row2.pack(fill=tk.X)
        tk.Label(row2, text="Family:").pack(side=tk.LEFT)
        self.family_var = tk.StringVar(value=self._initial_family)
        self.family_combo = ttk.Combobox(row2, textvariable=self.family_var, width=8,
                                         values=FAMILIES, state="readonly")
        self.family_combo.pack(side=tk.LEFT, padx=(4, 8))
        self.family_combo.bind("<<ComboboxSelected>>", lambda _e: self.reset_emulator())

        tk.Label(row2, text="Sidecar:").pack(side=tk.LEFT)
        self.sidecar_var = tk.StringVar(value=self._initial_json)
        self.sidecar_combo = ttk.Combobox(row2, textvariable=self.sidecar_var, width=26,
                                          values=list(self._sidecar_presets.keys()))
        self.sidecar_combo.pack(side=tk.LEFT, padx=4)
        self.sidecar_combo.bind("<<ComboboxSelected>>", lambda _e: self.reset_emulator())
        tk.Button(row2, text="JSON...", command=self.browse_json, width=7).pack(side=tk.LEFT, padx=(0, 8))

        self.fast_mode_var = tk.BooleanVar(value=self._initial_fast)
        tk.Checkbutton(row2, text="Fast Mode", variable=self.fast_mode_var,
                       command=self._on_fast_mode_toggled).pack(side=tk.LEFT, padx=4)
        self.spi_dump_var = tk.BooleanVar(value=False)
        tk.Checkbutton(row2, text="SPI Trace", variable=self.spi_dump_var,
                       command=self._on_spi_dump_toggled).pack(side=tk.LEFT, padx=2)
        self._sync_dump_combo_display()
        
        # Controls
        control_frame = tk.LabelFrame(left_frame, text="Controls", padx=10, pady=10)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        btn_frame = tk.Frame(control_frame)
        btn_frame.pack()
        
        tk.Button(btn_frame, text="Step Into (F11)", command=self.step_into, width=15, bg="#4CAF50", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="Step Over (F10)", command=self.step_over, width=15, bg="#2196F3", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="Step Skip (F8)", command=self.step_skip, width=15, bg="#008CBA", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="Step Out (Sh+F11)", command=self.step_out, width=15, bg="#9C27B0", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="Run (F5)", command=self.run_continuous, width=10, bg="#FF9800", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="Pause (F6)", command=self.pause_execution, width=10, bg="#FFC107", fg="black").pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="Reset", command=self.reset_emulator, width=10, bg="#F44336", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text="Screen", command=self.show_screen, width=10, bg="#607D8B", fg="white").pack(side=tk.LEFT, padx=2)

        self.root.bind('<F11>', self.step_into)
        self.root.bind('<F10>', self.step_over)
        self.root.bind('<F8>', self.step_skip)
        self.root.bind('<Shift-F11>', self.step_out)
        self.root.bind('<F5>', lambda e: self.run_continuous())
        self.root.bind('<F6>', lambda e: self.pause_execution())

        # Instructions
        instr_frame = tk.LabelFrame(left_frame, text="Instructions", padx=5, pady=5)
        instr_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        text_scroll = tk.Scrollbar(instr_frame)
        text_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.instr_text = tk.Text(instr_frame, wrap=tk.NONE, font=("Courier New", 10), 
                                  yscrollcommand=text_scroll.set, bg="#1E1E1E", fg="#D4D4D4",
                                  insertbackground="white", selectbackground="#264F78")
        self.instr_text.pack(fill=tk.BOTH, expand=True)
        text_scroll.config(command=self.instr_text.yview)
        
        self.instr_text.tag_config("current", background="#264F78", foreground="#FFFFFF")
        self.instr_text.tag_config("breakpoint", background="#8B0000", foreground="#FFFFFF")
        self.instr_text.tag_config("prev", foreground="#808080")
        self.instr_text.tag_config("next", foreground="#A0A0A0")
        self.instr_text.tag_config("loop", foreground="#FFD700")

        # Context Menu for Breakpoints
        self.instr_text.bind("<Button-3>", self.show_context_menu)

        # Right Panel
        right_frame = tk.Frame(main_paned)
        main_paned.add(right_frame, width=600)
        
        # Breakpoints
        bp_frame = tk.LabelFrame(right_frame, text="Breakpoints", padx=5, pady=5)
        bp_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        bp_btn_frame = tk.Frame(bp_frame)
        bp_btn_frame.pack(fill=tk.X)
        tk.Button(bp_btn_frame, text="Add", command=self.add_breakpoint, width=10).pack(side=tk.LEFT, padx=2)
        tk.Button(bp_btn_frame, text="Edit", command=self.edit_breakpoint, width=10).pack(side=tk.LEFT, padx=2)
        tk.Button(bp_btn_frame, text="Remove", command=self.remove_breakpoint, width=10).pack(side=tk.LEFT, padx=2)
        self.bp_listbox = tk.Listbox(bp_frame, font=("Courier New", 10))
        self.bp_listbox.pack(fill=tk.BOTH, expand=True)
        self.update_breakpoint_list()
        
        # Watches
        watch_frame = tk.LabelFrame(right_frame, text="Memory Watches", padx=5, pady=5)
        watch_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        watch_btn_frame = tk.Frame(watch_frame)
        watch_btn_frame.pack(fill=tk.X)
        tk.Button(watch_btn_frame, text="Direct", command=self.add_direct_watch, width=8).pack(side=tk.LEFT, padx=1)
        tk.Button(watch_btn_frame, text="Pointer", command=self.add_pointer_watch, width=8).pack(side=tk.LEFT, padx=1)
        tk.Button(watch_btn_frame, text="Remove", command=self.remove_watch, width=8).pack(side=tk.LEFT, padx=1)
        tk.Button(watch_btn_frame, text="Write", command=self.write_test_value, width=8, bg="#FFA500", fg="white").pack(side=tk.LEFT, padx=1)
        self.watch_listbox = tk.Listbox(watch_frame, font=("Courier New", 9))
        self.watch_listbox.pack(fill=tk.BOTH, expand=True)
        self.update_watch_list()
        
        # Log
        log_frame = tk.LabelFrame(right_frame, text="Log", padx=5, pady=5)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text = tk.Text(log_frame, wrap=tk.WORD, height=8, font=("Courier New", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Bottom
        bottom_container = tk.Frame(self.root)
        bottom_container.pack(fill=tk.BOTH, expand=False, side=tk.BOTTOM)
        
        # Registers
        reg_frame = tk.LabelFrame(bottom_container, text="Registers", padx=5, pady=5)
        reg_frame.pack(fill=tk.BOTH, expand=False, side=tk.LEFT, padx=5, pady=5)
        self.reg_labels = {}
        reg_names = [
            "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
            "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
            "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
            "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"
        ]
        for i, name in enumerate(reg_names):
            lbl = tk.Label(reg_frame, text=f"{name}: 00000000", font=("Courier New", 9), width=12, anchor=tk.W)
            lbl.grid(row=i//8, column=i%8, padx=1, pady=1)
            self.reg_labels[name] = lbl
        extras = ["PC", "HI", "LO"]
        for i, name in enumerate(extras):
            lbl = tk.Label(reg_frame, text=f"{name}: 00000000", font=("Courier New", 9, "bold"), width=12, anchor=tk.W)
            lbl.grid(row=4, column=i, padx=1, pady=1)
            self.reg_labels[name] = lbl
            
        # UART / SPI Tabs
        io_notebook = ttk.Notebook(bottom_container)
        io_notebook.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=5, pady=5)

        # UART Tab
        uart_tab = tk.Frame(io_notebook)
        io_notebook.add(uart_tab, text="UART")
        uart_scroll = tk.Scrollbar(uart_tab)
        uart_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.uart_text = tk.Text(uart_tab, wrap=tk.WORD, height=8, width=40, font=("Courier New", 9),
                                 bg="black", fg="#00FF00", yscrollcommand=uart_scroll.set)
        self.uart_text.pack(fill=tk.BOTH, expand=True)
        uart_scroll.config(command=self.uart_text.yview)
        uart_copy_btn = tk.Button(uart_tab, text="Copy", font=("Segoe UI", 7), padx=4, pady=1,
                                  command=lambda: self._copy_text(self.uart_text))
        uart_copy_btn.place(relx=1.0, rely=1.0, anchor="se", x=-20, y=-4)

        # SPI Tab
        spi_tab = tk.Frame(io_notebook)
        io_notebook.add(spi_tab, text="SPI")
        spi_scroll = tk.Scrollbar(spi_tab)
        spi_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.spi_text = tk.Text(spi_tab, wrap=tk.WORD, height=8, width=40, font=("Courier New", 9),
                                bg="black", fg="#FFB300", yscrollcommand=spi_scroll.set)
        self.spi_text.pack(fill=tk.BOTH, expand=True)
        spi_scroll.config(command=self.spi_text.yview)
        spi_copy_btn = tk.Button(spi_tab, text="Copy", font=("Segoe UI", 7), padx=4, pady=1,
                                 command=lambda: self._copy_text(self.spi_text))
        spi_copy_btn.place(relx=1.0, rely=1.0, anchor="se", x=-20, y=-4)
        
        # Status Bar
        status_frame = tk.Frame(self.root, relief=tk.SUNKEN, bd=1)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_label = tk.Label(status_frame, text="Ready", anchor=tk.W, font=("Courier New", 9))
        self.status_label.pack(fill=tk.X, padx=5)

    # -------------------------------------------------------------------------
    # Breakpoint/Watch Management (Boilerplate)
    # -------------------------------------------------------------------------
    def show_context_menu(self, event):
        try:
            # Find which line was clicked
            index = self.instr_text.index(f"@{event.x},{event.y}")
            line_text = self.instr_text.get(index + " linestart", index + " lineend")
            
            # Parse address from line "0xXXXXXXXX: ..."
            if line_text.strip().startswith("0x"):
                parts = line_text.strip().split(":")
                if len(parts) > 0:
                    addr_str = parts[0]
                    try:
                        address = int(addr_str, 16)
                    except ValueError:
                        return

                    # Create context menu
                    menu = tk.Menu(self.root, tearoff=0)
                    if address in self.breakpoints:
                        menu.add_command(label=f"Remove Breakpoint (0x{address:08X})", 
                                         command=lambda: self.toggle_breakpoint(address))
                    else:
                        menu.add_command(label=f"Add Breakpoint (0x{address:08X})", 
                                         command=lambda: self.toggle_breakpoint(address))
                        menu.add_command(label=f"Add Named Breakpoint...", 
                                         command=lambda: self.add_named_breakpoint_at(address))
                                         
                    menu.add_separator()
                    if address in self.forced_mips16_addresses:
                         menu.add_command(label=f"Unforce MIPS16 View", 
                                          command=lambda: self.toggle_mips16_force(address))
                    else:
                         menu.add_command(label=f"Force MIPS16 View", 
                                          command=lambda: self.toggle_mips16_force(address))
                    
                    menu.tk_popup(event.x_root, event.y_root)
        except Exception as e:
            self.log(f"Context menu error: {e}")

    def toggle_breakpoint(self, address):
        if address in self.breakpoints:
            del self.breakpoints[address]
            self.log(f"Breakpoint removed at 0x{address:08X}")
        else:
            self.breakpoints[address] = "User"
            self.log(f"Breakpoint added at 0x{address:08X}")
            
        self.save_breakpoints()
        self.update_breakpoint_list()
        self.update_instruction_display()

    def toggle_mips16_force(self, address):
        """Toggle forced 16-bit display for a region starting at address"""
        if address in self.forced_mips16_addresses:
            self.forced_mips16_addresses.remove(address)
            self.log(f"Unforced MIPS16 at 0x{address:08X}")
        else:
            self.forced_mips16_addresses.add(address)
            self.log(f"Forced MIPS16 at 0x{address:08X}")
            
        self.update_instruction_display()

    def add_named_breakpoint_at(self, address):
        name = simpledialog.askstring("Add BP", f"Name for 0x{address:08X}:")
        if name is not None:
            self.breakpoints[address] = name
            self.log(f"Breakpoint added at 0x{address:08X}")
            self.save_breakpoints()
            self.update_breakpoint_list()
            self.update_instruction_display()

    def add_breakpoint(self):
        addr_str = simpledialog.askstring("Add BP", "Address (hex):")
        if addr_str:
            try:
                addr = int(addr_str, 16)
                name = simpledialog.askstring("Add BP", "Name (optional):")
                self.breakpoints[addr] = name
                self.save_breakpoints()
                self.update_breakpoint_list()
                self.update_instruction_display()
            except: messagebox.showerror("Error", "Invalid address")

    def edit_breakpoint(self):
        sel = self.bp_listbox.curselection()
        if not sel: return
        item = self.bp_listbox.get(sel[0])
        old_addr = int(item.split()[0], 16)
        new_addr_str = simpledialog.askstring("Edit BP", "Address:", initialvalue=f"0x{old_addr:X}")
        if new_addr_str:
            try:
                new_addr = int(new_addr_str, 16)
                del self.breakpoints[old_addr]
                self.breakpoints[new_addr] = simpledialog.askstring("Edit BP", "Name:")
                self.save_breakpoints()
                self.update_breakpoint_list()
            except: pass

    def remove_breakpoint(self):
        sel = self.bp_listbox.curselection()
        if not sel: return
        item = self.bp_listbox.get(sel[0])
        addr = int(item.split()[0], 16)
        if addr in self.breakpoints:
            del self.breakpoints[addr]
            self.save_breakpoints()
            self.update_breakpoint_list()
            self.update_instruction_display()
            
    def update_breakpoint_list(self):
        self.bp_listbox.delete(0, tk.END)
        for addr in sorted(self.breakpoints.keys()):
            name = self.breakpoints[addr]
            self.bp_listbox.insert(tk.END, f"0x{addr:08X} {f'({name})' if name else ''}")
            
    def save_breakpoints(self):
        try:
            data = [{"addr": k, "name": v} for k,v in self.breakpoints.items()]
            with open("breakpoints.json", "w") as f: json.dump(data, f)
        except: pass
        
    def load_breakpoints(self):
        try:
            if os.path.exists("breakpoints.json"):
                with open("breakpoints.json") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict): self.breakpoints[item.get("addr")] = item.get("name")
                            elif isinstance(item, int): self.breakpoints[item] = None # Legacy
        except: pass

    def add_direct_watch(self):
        addr = simpledialog.askstring("Watch", "Address (hex):")
        length = simpledialog.askstring("Watch", "Length:")
        if addr and length:
            try:
                self.watches.append({'type': 'direct', 'address': int(addr,16), 'length': int(length), 'break_on_change': True})
                self.save_watches()
                self.update_watch_list()
            except: pass

    def add_pointer_watch(self):
        ptr = simpledialog.askstring("Watch", "Pointer Address (hex):")
        off = simpledialog.askstring("Watch", "Offset (default 0):", initialvalue="0")
        length = simpledialog.askstring("Watch", "Length:")
        if ptr and length:
            try:
                self.watches.append({'type': 'pointer', 'ptr_address': int(ptr,16), 'offset': int(off or 0), 'length': int(length), 'break_on_change': True})
                self.save_watches()
                self.update_watch_list()
            except: pass

    def remove_watch(self):
        sel = self.watch_listbox.curselection()
        if sel:
            idx = sel[0]
            self.watches.pop(idx)
            if idx in self.watch_previous_values: del self.watch_previous_values[idx]
            self.save_watches()
            self.update_watch_list()

    def update_watch_list(self):
        self.watch_listbox.delete(0, tk.END)
        for i, watch in enumerate(self.watches):
            try:
                if self.sim:
                    if watch['type'] == 'direct':
                        val = self.sim.peek(watch['address'], watch['length'])
                        if watch['length'] <= 4:
                            val_int = int.from_bytes(val, 'little')
                            self.watch_listbox.insert(tk.END, f"[{i}] {hex(watch['address'])}: {val.hex()} ({val_int})")
                        else:
                            self.watch_listbox.insert(tk.END, f"[{i}] {hex(watch['address'])}: {val.hex()}")
                            
                    elif watch['type'] == 'pointer':
                        ptr_addr = watch['ptr_address']
                        offset = watch.get('offset', 0)
                        length = watch['length']
                        
                        ptr_bytes = self.sim.peek(ptr_addr, 4)
                        ptr_val = int.from_bytes(ptr_bytes, 'little')
                        actual_addr = ptr_val + offset
                        
                        val = self.sim.peek(actual_addr, length)
                        if length <= 4:
                            val_int = int.from_bytes(val, 'little')
                            self.watch_listbox.insert(tk.END, f"[{i}] *{hex(ptr_addr)}+{offset}->{hex(actual_addr)}: {val.hex()} ({val_int})")
                        else:
                            self.watch_listbox.insert(tk.END, f"[{i}] *{hex(ptr_addr)}+{offset}->{hex(actual_addr)}: {val.hex()}")
                else:
                    self.watch_listbox.insert(tk.END, f"[{i}] Watch (Sim not ready)")
            except Exception as e:
                self.watch_listbox.insert(tk.END, f"[{i}] Error: {e}")

    def save_watches(self):
        try:
            with open("watches.json", "w") as f: json.dump(self.watches, f)
        except: pass
        
    def load_watches(self):
        try:
            if os.path.exists("watches.json"):
                with open("watches.json") as f: self.watches = json.load(f)
        except: pass
        
    def write_test_value(self):
        if not self.sim: return
        addr = simpledialog.askstring("Write", "Address (hex):")
        val = simpledialog.askstring("Write", "Value (hex):")
        if addr and val:
            try:
                self.sim.poke(int(addr, 16), int(val, 16).to_bytes(4, 'little'))
                self.log(f"Wrote {val} to {addr}")
                self.update_watch_list()
            except Exception as e: messagebox.showerror("Error", str(e))

def main():
    args = sys.argv[1:]
    family = "Auto"
    json_path = None
    fast = False
    if "--family" in args:
        i = args.index("--family")
        family = args[i + 1]
        del args[i:i + 2]
    if "--json" in args:
        i = args.index("--json")
        json_path = args[i + 1]
        del args[i:i + 2]
    if "--fast" in args:
        args.remove("--fast")
        fast = True
    binary = args[0] if args else "dump.bin"
    root = tk.Tk()
    app = MIPSSimulatorGUI(root, binary_file=binary, family=family, json_path=json_path, fast_mode=fast)
    root.mainloop()

if __name__ == "__main__":
    main()
