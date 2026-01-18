from simulator import AliMipsSimulator
import sys

# Configuration
INSTR_COUNT = 10000000
STOP_INSTR = None  
TRACE_INSTRUCTIONS = True

def main():
    sim = AliMipsSimulator()
    
    # Apply configuration
    sim.trace_instructions = TRACE_INSTRUCTIONS
    sim.stop_instr = STOP_INSTR
    
    # Load binary
    sim.loadFile("ali_sdk.bin")
    
    # Run
    sim.run(max_instructions=INSTR_COUNT)

if __name__ == "__main__":
    main()
