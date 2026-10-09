"""
Test: runs dump.bin with a garbage flash JEDEC ID to verify the bootloader
correctly reports "Can't find FLASH device!" when the ID doesn't match.
"""
import uart_regression


def garbage_jedec_id(sim):
    sim._spi_jedec_id = [0xDE, 0xAD, 0xFF]      # matches no entry of the bootloader's flash table


uart_regression.run("dump.bin", setup=garbage_jedec_id, stop_at="Can't find FLASH device!",
                    expected=["Can't find FLASH device!"], title="garbage flash JEDEC ID is reported")
