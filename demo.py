from simulator import AliMipsSimulator
import sys

def main():
    sim = AliMipsSimulator()
    
    # Configure logging
    # sim.setLogHandler(print) # Default is print anyway
    
    # Load binary
    sim.loadFile("ali_sdk.bin")
    
    # Run
    sim.run()

if __name__ == "__main__":
    main()
