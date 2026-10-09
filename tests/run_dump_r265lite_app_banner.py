#!/usr/bin/env python3
"""The intact Opticum Blue R265 Lite firmware (T2GEN265 1.1.5, the official update image)
boots through the M3821 bootloader stages into its application, which prints its banner.
"""
import uart_regression

uart_regression.run("T2GEN265_1.1.5-2022-08-01.abs", stop_at="Application version 1.0.0",
                    max_instructions=60_000_000,
                    title="Opticum Blue R265 Lite firmware 1.1.5 (M3821) boots into its application",
                    expected=["NOR1", "2X", "MC: APP  init ok", "<< SDK4.0ba.4.0_20101217 >>",
                              "Libcore version 19.9.d", "Application version 1.0.0"])
