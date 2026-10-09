#!/usr/bin/env python3
"""The newest Opticum Blue R265 Lite firmware (T2GEN265 1.2.0, the official update image)
boots through its 2023 bootloader build -- silent on the UART, and it reads the flash through
the SPI controller's byte-stream mode word by word -- into its application, which prints its
banner (a newer Libcore than firmware 1.1.5's).
"""
import uart_regression

uart_regression.run("T2GEN265_1.2.0-2023-03-17.abs", stop_at="Application version 1.0.0",
                    max_instructions=80_000_000,
                    retries=2,      # its stage 2 trips the simulator's slice-stop race about one boot in three
                                    # under load (an unmapped read at PC 0)
                    title="Opticum Blue R265 Lite firmware 1.2.0 (M3821) boots into its application",
                    expected=["MC: APP  init ok", "<< SDK4.0ba.4.0_20101217 >>",
                              "Libcore version 19.17.0", "Application version 1.0.0"])
