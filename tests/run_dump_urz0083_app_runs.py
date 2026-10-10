#!/usr/bin/env python3
"""The Cabletech URZ0083 firmware V1.2.5 (ALi M3601E, the M36xx generation: chips/m3602.py) boots
into its application, which prints its banners and a dump of strap registers and then keeps
running.  With the M3801's chip ID (0x3811, not in its chip table) the application started over
through the bootloader every ~45 M instructions, printing the banner again at ~71 M.
"""
import uart_regression

uart_regression.run("URZ0083_V1.2.5.abs", max_instructions=80_000_000,
                    title="Cabletech URZ0083 V1.2.5 (M36xx) runs its application without starting over",
                    expected=["MC: APP  init ok", "<< SDK4.0ba.4.2_20110225 >>",
                              "Libcore version 6.4.0@SDK4.0ba.6.4_20111019",
                              "Application version 1.0.0@SDK4.0ba.6.4_GLS_T_20111019",
                              "0xb8018504 = 0x00000064"],
                    once=["MC: APP  init ok"])
