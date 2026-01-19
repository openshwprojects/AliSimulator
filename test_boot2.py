from simulator import AliMipsSimulator
from unicorn import *
from unicorn.mips_const import *
from mips16_decoder import MIPS16Decoder

def main():
    # Initialize simulator with a dummy log handler to silence initial output
    # User requested "runs silently", so we suppress the default print logging.
    sim = AliMipsSimulator(log_handler=lambda msg: None)

    # Load firmware
    try:
        sim.loadFile("dump.bin")
    except FileNotFoundError:
        print("Error: dump.bin not found.")
        return

    # Trigger address
    TRIGGER_ADDRESS = 0x81E8E1B8
    LIMIT_INSTRUCTIONS = 30
    
    # Context to track status
    context = {
        "active": False,
        "count": 0
    }

    print(f"Running silently until {hex(TRIGGER_ADDRESS)}...")

    def hook_code(uc, address, size, user_data):
        # Check if we hit the trigger
        if not context["active"] and address == TRIGGER_ADDRESS:
            context["active"] = True
            print(f"\n[!] Trigger reached at 0x{address:08X}")

        # If active, dump instructions
        if context["active"]:
            if context["count"] < LIMIT_INSTRUCTIONS:
                try:
                    code = uc.mem_read(address, size)
                    
                    hex_str = ' '.join(f'{b:02x}' for b in code)
                    
                    # Check for MIPS16 (size 2)
                    if size == 2:
                        # Decode MIPS16 instruction
                        mnemonic, operands = MIPS16Decoder.decode(code)
                        hex_fmt = f"{hex_str:<11}"
                        print(f"0x{address:08X}: {hex_fmt} {mnemonic}\t{operands}")
                    else:
                        # Standard MIPS32 (or MIPS16 4-byte instruction)
                        instr_list = list(sim.md.disasm(code, address))
                        if instr_list:
                            for instr in instr_list:
                                # Align hex string for prettiness (max 4 bytes = 11 chars)
                                hex_fmt = f"{hex_str:<11}"
                                print(f"0x{instr.address:08X}: {hex_fmt} {instr.mnemonic}\t{instr.op_str}")
                        else:
                            print(f"0x{address:08X}: [RAW]    {hex_str}")

                except Exception as e:
                    print(f"0x{address:08X}: [Error Disassembling: {e}]")
                
                context["count"] += 1
            else:
                print(f"Dumped {LIMIT_INSTRUCTIONS} instructions. Stopping.")
                uc.emu_stop()

    # Add the hook
    sim.mu.hook_add(UC_HOOK_CODE, hook_code)

    # Run Loop
    # We use a custom loop to handle manual fixes (LUI, etc) and ensure we stop properly.
    target_len = sim.rom_size
    start_pc = sim.base_addr
    end_addr = start_pc + target_len
    
    # Safety
    max_steps = 20000000 # 20M instructions limit (adjust if needed, boot can be long)
    steps = 0

    cur_pc = sim.mu.reg_read(UC_MIPS_REG_PC)

    while cur_pc < end_addr and steps < max_steps:
        # Check if we are done dumping
        if context["active"] and context["count"] >= LIMIT_INSTRUCTIONS:
            break

        # Required by simulator engine for correctness
        sim.apply_manual_fixes()
        sim.invalidate_jit(cur_pc)

        try:
            # Run simulation
            sim.mu.emu_start(cur_pc, end_addr)
        except UcError as e:
            # If emu_stop() was called (e.g. from hook), we catch it here.
            # Also catch other errors silently or handled by hook logic
            pass
        
        cur_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
        steps += 1
        
        # Periodic update if it takes too long (optional, kept silent for now as requested)

    if not context["active"]:
        print(f"Warning: Reached end of run (or limit) without hitting {hex(TRIGGER_ADDRESS)}")

if __name__ == "__main__":
    main()
