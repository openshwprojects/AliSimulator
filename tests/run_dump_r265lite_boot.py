"""
Regression test: the Opticum Blue R265 Lite image (M3822P.bin, the ALi M3821
family, see chips/m3821.py) boots as far as its flash lets it: the boot ROM's
copy of the bootloader into the boot SRAM and the entry at 0x9FE00800, stage 1
("NOR1" on the UART, the clock tree, the DDR training against the simulator's
DDR model, "2", the copy of stage 2 into RAM, "X"), and stage 2 (the TDS-style
"\\x01" and the walk of the NCRC chunk chain through the SPI flash driver).

Stage 2 then stops in its recovery loop: the main-code chunk of this dump fails
the bootloader's own CRC check (its LZMA stream is damaged 0x77000 bytes in,
see the dump's note), and no recovery image (chunk id 0x00FF0000) exists, so
the box this flash came from halts at the same point.
"""
import uart_regression

uart_regression.run("M3822P.bin", stop_at="\x01", max_instructions=20_000_000,
                    title="Opticum Blue R265 Lite (M3821) boots through stage 1, the DDR training and stage 2",
                    expected=["NOR1", "2X", "\x01"])
