from simulator import AliMipsSimulator
import sys

# ANSI colors
GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

EXPECTED_OUTPUT = """Booting...
Main function
stack end: 82000000
stack start: 82008000
heap start: 81000954
heap end: 81008954
cause: 0
x: 1.230000 y: 1.250000
result: 25.729999
cause: 0
chip id raw: 3811
Menu!
"""

class RealTimeVerifier:
    def __init__(self, expected):
        self.expected = expected
        self.index = 0
        self.failed = False
        self.output_buffer = ""
        self.started = False

    def on_uart(self, char):
        # Ignore \r (Carriage Return) to simplify matching against \n
        if char == '\r':
            return

        # Buffer for debug if needed
        self.output_buffer += char

        if not self.started:
            if char == self.expected[0]:
                self.started = True
            else:
                # Ignore garbage before start, maybe print lightly or just invalid
                # sys.stdout.write(char) # optional
                return

        match = False
        if self.index < len(self.expected):
            if char == self.expected[self.index]:
                match = True
        
        if match:
            sys.stdout.write(GREEN + char + RESET)
            self.index += 1
        else:
            sys.stdout.write(RED + char + RESET)
            # failure debug
            expected = 'None'
            if self.index < len(self.expected):
                expected = repr(self.expected[self.index])
            sys.stdout.write(f"{RED}[EXP:{expected}]{RESET}")
            
            self.failed = True
            self.index += 1
            
        sys.stdout.flush()

    def finish(self):
        print(RESET) # Ensure reset
        if self.failed:
            print(f"\n{RED}TEST FAILED (Mismatch occurred){RESET}")
        elif self.index == 0:
             print(f"\n{RED}TEST FAILED (No Output){RESET}")
        else:
            # Check if we matched everything
            if self.index < len(self.expected):
                print(f"\n{RED}TEST PARTIAL (Missing end of output){RESET}")
            else:
                print(f"\n{GREEN}TEST PASSED{RESET}")

def main():
    verifier = RealTimeVerifier(EXPECTED_OUTPUT)
    
    # Silence internal logs
    # sim = AliMipsSimulator(log_handler=lambda x: None)
    sim = AliMipsSimulator() # Default logs to print
    sim.setUartHandler(verifier.on_uart)
    
    sim.loadFile("ali_sdk.bin")
    
    # 60k is enough, tested for this specific bin
    sim.run(max_instructions=60000)
    
    verifier.finish()

if __name__ == "__main__":
    main()
