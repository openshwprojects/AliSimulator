import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from unicorn import *
from unicorn.mips_const import *
from capstone import *
import json
import os
import threading
from simulator import AliMipsSimulator
from mips16_decoder import MIPS16Decoder

class MIPSSimulatorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MIPS Simulator - GUI Debugger (New Engine)")
        self.root.geometry("1400x900")
        
        self.BINARY_FILE = "dump.bin"
        
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
        
        # Temp breakpoints for stepping
        self.temp_breakpoints = set()
        
        # Address to ignore (for stepping over BPs)
        self.ignore_bp_addr = None

        # Load persistent data
        self.load_breakpoints()
        self.load_watches()
        
        # Create GUI
        self.create_gui()
        
        # Initialize Emulator
        self.init_emulator()

    def _step_over_breakpoint(self):
        """Helper to step exactly one instruction ignoring any breakpoint at current PC"""
        pc = self.sim.mu.reg_read(UC_MIPS_REG_PC)
        self.ignore_bp_addr = pc
        try:
            self.sim.runStep()
        finally:
            self.ignore_bp_addr = None
        
    def log(self, message):
        """Add message to log"""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)

    def on_uart_write(self, char):
        """Handle UART output"""
        # Only print valid chars
        if isinstance(char, int):
            char = chr(char & 0xFF)
            
        if char.isprintable() or char in ['\n', '\r', '\t']:
             self.uart_text.insert(tk.END, char)
             self.uart_text.see(tk.END)

    def init_emulator(self):
        """Initialize the simulator backend"""
        try:
            # Create simulator instance
            # We pass our log method as the handler
            self.sim = AliMipsSimulator(log_handler=self.log)
            self.sim.setUartHandler(self.on_uart_write)
            
            # Load the binary
            self.sim.loadFile(self.BINARY_FILE)
            
            # Add GUI-specific hooks
            # Breakpoints (User + Temp)
            self.sim.mu.hook_add(UC_HOOK_CODE, self.hook_breakpoints)
            
            # Printf hook (Legacy support from old GUI)
            self.sim.mu.hook_add(UC_HOOK_CODE, self.hook_printf, begin=0xAFC00494, end=0xAFC00494)
            
            # Initialize GUI displays
            self.update_ui_safe()
            self.log("Simulator initialized successfully using simulator.py backend")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initialize simulator: {e}")
            
    def reset_emulator(self):
        """Reset the emulator"""
        self.is_running = False
        self.paused = False
        self.temp_breakpoints.clear()
        self.init_emulator()

    # -------------------------------------------------------------------------
    # Hooks
    # -------------------------------------------------------------------------
    def hook_breakpoints(self, uc, address, size, user_data):
        # Check user breakpoints
        # Check user breakpoints
        if address in self.breakpoints:
             if self.ignore_bp_addr is not None and address == self.ignore_bp_addr:
                 # Skip this breakpoint once
                 return

             # Standard behavior: Stop.
             self.log(f"Breakpoint hit at 0x{address:08X}")
             uc.emu_stop()
             self.is_running = False
             self.paused = True 
             return

        # Check temp breakpoints (stepping)
        if address in self.temp_breakpoints:
             uc.emu_stop()
             self.is_running = False
             return

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
        """Execute one instruction using the backend"""
        try:
            pc = self.sim.mu.reg_read(UC_MIPS_REG_PC)
            if pc in self.breakpoints:
                # Use special step helper
                self._step_over_breakpoint()
            else:
                self.sim.runStep()
                
            self.check_watches()
            # Update UI immediately for single step
            self.update_ui_safe()
            return True
        except Exception as e:
            self.log(f"Step error: {e}")
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
        
        # Analyze current instruction
        try:
            pc = self.sim.mu.reg_read(UC_MIPS_REG_PC)
            code_bytes = self.sim.mu.mem_read(pc, 4)
            instrs = list(self.sim.md.disasm(code_bytes, pc))
            
            if instrs:
                instr = instrs[0]
                # Check for JAL, JALR, BAL
                if instr.mnemonic in ['jal', 'jalr', 'bal']:
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
        """Run execution loop"""
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
                
                while self.is_running and not self.paused:
                    # 1. Apply manual fixes (LUI etc) needed by the backend
                    self.sim.apply_manual_fixes()
                    
                    # 2. Get PC and invalidate JIT for self-modifying code support
                    current_pc = self.sim.mu.reg_read(UC_MIPS_REG_PC)
                    self.sim.invalidate_jit(current_pc)
                    
                    # 3. Run a chunk of instructions
                    # Use a reasonable block size to keep UI responsive-ish
                    CHUNK_SIZE = 10000 
                    end_addr = self.sim.base_addr + self.sim.rom_size
                    
                    try:
                        self.sim.mu.emu_start(current_pc, end_addr, count=CHUNK_SIZE)
                    except UcError:
                        # Error or Stop request?
                        # If stopped by hook, it's fine.
                        pass
                    
                    # 4. Check status
                    # If we hit a breakpoint hook, it sets self.is_running = False
                    if not self.is_running or self.paused:
                        break
                        
                    # 5. Check watches occasionally
                    if self.sim.instruction_count % 50000 < CHUNK_SIZE:
                        if self.check_watches():
                            self.is_running = False
                            self.paused = True
                            break
                        # Periodic UI update
                        self.root.after(0, self.update_ui_safe)
                        
            except Exception as e:
                self.log(f"Execution Error: {e}")
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
        self.update_instruction_display()
        self.update_status()
        self.update_registers()
        # self.update_watch_list() # Keeps watches updated? Yes.

    def update_status(self):
        if not self.sim: return
        try:
            pc = self.sim.mu.reg_read(UC_MIPS_REG_PC)
            status = f"PC: 0x{pc:08X} | Instructions: {self.sim.instruction_count}"
            if self.is_running: status += " | [RUNNING]"
            elif self.paused: status += " | [PAUSED]"
            else: status += " | [STOPPED]"
            self.status_label.config(text=status)
        except: pass

    def update_registers(self):
        if not self.sim: return
        try:
            reg_map = {
                "zero": UC_MIPS_REG_ZERO, "at": UC_MIPS_REG_AT, "v0": UC_MIPS_REG_V0, "v1": UC_MIPS_REG_V1,
                "a0": UC_MIPS_REG_A0, "a1": UC_MIPS_REG_A1, "a2": UC_MIPS_REG_A2, "a3": UC_MIPS_REG_A3,
                "t0": UC_MIPS_REG_T0, "t1": UC_MIPS_REG_T1, "t2": UC_MIPS_REG_T2, "t3": UC_MIPS_REG_T3,
                "t4": UC_MIPS_REG_T4, "t5": UC_MIPS_REG_T5, "t6": UC_MIPS_REG_T6, "t7": UC_MIPS_REG_T7,
                "s0": UC_MIPS_REG_S0, "s1": UC_MIPS_REG_S1, "s2": UC_MIPS_REG_S2, "s3": UC_MIPS_REG_S3,
                "s4": UC_MIPS_REG_S4, "s5": UC_MIPS_REG_S5, "s6": UC_MIPS_REG_S6, "s7": UC_MIPS_REG_S7,
                "t8": UC_MIPS_REG_T8, "t9": UC_MIPS_REG_T9, "k0": UC_MIPS_REG_K0, "k1": UC_MIPS_REG_K1,
                "gp": UC_MIPS_REG_GP, "sp": UC_MIPS_REG_SP, "fp": UC_MIPS_REG_FP, "ra": UC_MIPS_REG_RA,
                "PC": UC_MIPS_REG_PC, "HI": UC_MIPS_REG_HI, "LO": UC_MIPS_REG_LO
            }
            
            for name, const in reg_map.items():
                val = self.sim.mu.reg_read(const)
                lbl = self.reg_labels.get(name)
                if lbl:
                    if name in ["PC", "sp", "ra"]: lbl.config(fg="blue")
                    elif val != 0: lbl.config(fg="black")
                    else: lbl.config(fg="gray")
                    lbl.config(text=f"{name.upper()}: {val:08X}")
        except: pass

    def get_instructions_around_pc(self, pc, before=10, after=10):
        if not self.sim: return []
        instructions = []
        
        # Backward scan (Tricky with variable length)
        # Strategy: Go back 'before * 4' bytes (approx), then disassemble forward.
        # If we desync at PC, adjust start point.
        
        start_attempts = [pc - (before * 4), pc - (before * 4) + 2]
        best_instrs = []
        
        for start_addr in start_attempts:
            if start_addr < 0: continue
            
            # Check if PC is a JALX target before scanning
            pc_is_jalx_target = False
            prev_exec = getattr(self.sim, 'prev_executed_pc', None)
            if prev_exec:
                try:
                    prev_bytes = self.sim.mu.mem_read(prev_exec, 4)
                    prev_disasm = list(self.sim.md.disasm(prev_bytes, prev_exec))
                    if prev_disasm and prev_disasm[0].mnemonic == 'jalx':
                        pc_is_jalx_target = True
                        print(f"[DEBUG] PC 0x{pc:08X} is JALX target from 0x{prev_exec:08X}")
                except: pass
            
            temp_instrs = []
            curr = start_addr
            # Disassemble until we hit PC or pass it
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
                    known_size = self.sim.instruction_sizes.get(curr)
                    if known_size == 2:
                        is_mips16 = True
                        print(f"[DEBUG] 0x{curr:08X} is MIPS16 from execution history")
                    
                    # 2. Forced Address (Manual Toggle)
                    if curr in self.forced_mips16_addresses:
                        is_mips16 = True
                        print(f"[DEBUG] 0x{curr:08X} is MIPS16 from forced addresses")
                    
                    # 3. JALX target detection
                    if not is_mips16 and curr == pc and pc_is_jalx_target:
                        is_mips16 = True
                        in_mips16_region = True  # Enter MIPS16 region
                        print(f"[DEBUG] 0x{curr:08X} is MIPS16 as JALX target - entering MIPS16 region")
                    
                    # 4. If we're in a MIPS16 region (and no execution history says otherwise), assume MIPS16
                    if not is_mips16 and in_mips16_region and known_size != 4:
                        is_mips16 = True
                        print(f"[DEBUG] 0x{curr:08X} is MIPS16 from region continuation")

                    if is_mips16:
                        # It's MIPS16! Decode it properly
                        valid_bytes = self.sim.mu.mem_read(curr, 2)
                        bytes_str = ' '.join(f'{b:02x}' for b in valid_bytes)
                        
                        # Decode MIPS16 instruction
                        mnemonic, operands = MIPS16Decoder.decode(valid_bytes)
                        
                        temp_instrs.append({
                            'address': curr,
                            'bytes': bytes_str,
                            'mnemonic': mnemonic,
                            'operands': operands,
                            'loop_count': self.sim.visit_counts.get(curr, 0),
                            'is_current': (curr == pc),
                            'is_breakpoint': (curr in self.breakpoints)
                        })
                        curr += 2
                        if curr == pc: valid_sequence = True
                        if curr > pc and not valid_sequence: break
                        if valid_sequence:
                             # check after count
                             count_after = sum(1 for i in temp_instrs if i['address'] > pc)
                             if count_after >= after: break
                        continue

                    # Try to disassemble as MIPS32 first
                    code = self.sim.mu.mem_read(curr, 4)
                    disasm = list(self.sim.md.disasm(code, curr))
                    
                    if not disasm:
                        # Fallback: treat as MIPS16 instruction
                        try:
                            valid_bytes = self.sim.mu.mem_read(curr, 2)
                            bytes_str = ' '.join(f'{b:02x}' for b in valid_bytes)
                            mnemonic, operands = MIPS16Decoder.decode(valid_bytes)
                            temp_instrs.append({
                                'address': curr,
                                'bytes': bytes_str,
                                'mnemonic': mnemonic,
                                'operands': operands,
                                'loop_count': self.sim.visit_counts.get(curr, 0),
                                'is_current': (curr == pc),
                                'is_breakpoint': (curr in self.breakpoints)
                            })
                            curr += 2
                        except:
                            curr += 4  # Skip if read fails
                        continue
                        
                    instr = disasm[0]
                    
                    item = {
                        'address': curr,
                        'bytes': ' '.join(f'{b:02x}' for b in instr.bytes),
                        'mnemonic': instr.mnemonic,
                        'operands': instr.op_str,
                        'loop_count': self.sim.visit_counts.get(curr, 0),
                        'is_current': (curr == pc),
                        'is_breakpoint': (curr in self.breakpoints)
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
            # Ultimate fallback: Show raw hex dump around PC
            print(f"[DEBUG] No valid disassembly found, using hex dump fallback at PC=0x{pc:08X}")
            curr = max(0, pc - 20)  # Show a bit before PC
            for i in range(25):  # Show ~50 bytes
                try:
                    # Try 2-byte MIPS16 first
                    code = self.sim.mu.mem_read(curr, 2)
                    mnemonic, operands = MIPS16Decoder.decode(code)
                    bytes_str = ' '.join(f'{b:02x}' for b in code)
                    best_instrs.append({
                        'address': curr,
                        'bytes': bytes_str,
                        'mnemonic': mnemonic,
                        'operands': operands,
                        'loop_count': self.sim.visit_counts.get(curr, 0),
                        'is_current': (curr == pc),
                        'is_breakpoint': (curr in self.breakpoints)
                    })
                    curr += 2
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

    def update_instruction_display(self):
        self.instr_text.delete(1.0, tk.END)
        try:
            pc = self.sim.mu.reg_read(UC_MIPS_REG_PC)
            instructions = self.get_instructions_around_pc(pc, before=15, after=15)
            
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
                    current_value = self.sim.mu.mem_read(addr, length)
                elif watch['type'] == 'pointer':
                    ptr_addr = watch['ptr_address']
                    offset = watch.get('offset', 0)
                    length = watch['length']
                    ptr_bytes = self.sim.mu.mem_read(ptr_addr, 4)
                    ptr_value = int.from_bytes(ptr_bytes, byteorder='little')
                    addr = ptr_value + offset
                    current_value = self.sim.mu.mem_read(addr, length)
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
        main_paned.add(left_frame, width=800)
        
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
            
        # UART
        uart_frame = tk.LabelFrame(bottom_container, text="UART Output", padx=5, pady=5)
        uart_frame.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=5, pady=5)
        
        uart_scroll = tk.Scrollbar(uart_frame)
        uart_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.uart_text = tk.Text(uart_frame, wrap=tk.WORD, height=8, width=40, font=("Courier New", 9), 
                                 bg="black", fg="#00FF00", yscrollcommand=uart_scroll.set)
        self.uart_text.pack(fill=tk.BOTH, expand=True)
        
        uart_scroll.config(command=self.uart_text.yview)
        
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
                        val = self.sim.mu.mem_read(watch['address'], watch['length'])
                        if watch['length'] <= 4:
                            val_int = int.from_bytes(val, 'little')
                            self.watch_listbox.insert(tk.END, f"[{i}] {hex(watch['address'])}: {val.hex()} ({val_int})")
                        else:
                            self.watch_listbox.insert(tk.END, f"[{i}] {hex(watch['address'])}: {val.hex()}")
                            
                    elif watch['type'] == 'pointer':
                        ptr_addr = watch['ptr_address']
                        offset = watch.get('offset', 0)
                        length = watch['length']
                        
                        ptr_bytes = self.sim.mu.mem_read(ptr_addr, 4)
                        ptr_val = int.from_bytes(ptr_bytes, 'little')
                        actual_addr = ptr_val + offset
                        
                        val = self.sim.mu.mem_read(actual_addr, length)
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
                self.sim.mu.mem_write(int(addr, 16), int(val, 16).to_bytes(4, 'little'))
                self.log(f"Wrote {val} to {addr}")
                self.update_watch_list()
            except Exception as e: messagebox.showerror("Error", str(e))

def main():
    root = tk.Tk()
    app = MIPSSimulatorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
