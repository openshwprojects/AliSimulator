# dump.bin Firmware Analysis

ALI M3510 (chip ID `0x3811`) bootloader/firmware dump.

## Memory Map

| Address Range | Description |
|---|---|
| `0xAFC00000` | Boot ROM entry point (MIPS32) |
| `0x81E00000–0x81E8E000` | Main firmware body (MIPS16) |
| `0x81E8E000+` | Loader/trigger stubs (MIPS32) |
| `0x81E8E1B8` | MIPS32 entry after boot copy |
| `0x81E92xxx` | Data tables, pointers, globals |

## ISA Mode

Firmware uses **mixed MIPS32/MIPS16** execution:
- Boot ROM at `0xAFC00000` is MIPS32
- Main code at `0x81E00000–0x81E8E000` is mostly MIPS16
- Some MIPS32 "island" functions exist within the MIPS16 range (called via `JAL`, not `JALX`)

### Known MIPS32 Islands in MIPS16 Range

| Address | Function |
|---|---|
| `0x81E8CB10–0x81E8CBE8` | `FUN_81e8cb10` — chip ID reader (switch on `0xB8000002`) |
| `0x81E8DAEC–0x81E8DB08` | CP0 Count reader (`MFC0 v0, $9` + NOPs + `JR $RA`) |
| `0x81E8DDA4` | System control reg write (`0xB8000038`) |
| `0x81E8CD50` | Chip ID byte read |

## MMIO Registers

### UART — `0xB8018300` (16550 compatible)

| Offset | Name | Description |
|---|---|---|
| +0 (`0xB8018300`) | UTBR/URBR | TX/RX data register |
| +1 (`0xB8018301`) | UIER | Interrupt enable |
| +2 (`0xB8018302`) | UIIR/UFCR | Interrupt ID / FIFO control |
| +3 (`0xB8018303`) | ULCR | Line control |
| +4 (`0xB8018304`) | UMCR | Modem control |
| +5 (`0xB8018305`) | ULSR | Line status — bit 5 (0x20) = TX empty |
| +6 (`0xB8018306`) | UMSR | Modem status |

UART TX flow (`uart_write_char`):
1. Write char to `UTBR` (+0)
2. Poll `ULSR` (+5) bit 5 until TX empty
3. If timeout, retry up to 3 times

### System Registers — `0xB8000000`

| Address | R/W | Description |
|---|---|---|
| `0xB8000000` | R | Chip ID register (returns `0x3811xxxx`) |
| `0xB8000002` | R | Chip ID halfword (returns `0x3811`) |
| `0xB8000038` | W | System control (firmware writes `0x00010000` during flash init) |
| `0xB8000074` | W | Strap control register |

### SPI Flash Controller — `0xB802E000`

| Address | Offset | R/W | Description |
|---|---|---|---|
| `0xB802E098` | +0x98 | R/W | SPI command/data register |
| `0xB802E099` | +0x99 | R/W | SPI control register |
| `0xB802E09A` | +0x9A | R/W | SPI read data / status register |

SPI command flow:
1. Write control byte to `+0x99` (e.g., `0x09`, `0x08`)
2. Write SPI command to `+0x98` (e.g., `0x9F` for JEDEC ID)
3. Read response from `+0x9A`

## Boot Sequence

```
0xAFC00000  Boot ROM entry (MIPS32)
   ↓ copy firmware to RAM, configure CP0
0x81E8E1B8  Loader entry (MIPS32)
   ↓ JALX to MIPS16 code
0x81E85Axx  MIPS16 main init
   ↓ busy-wait loops (CP0 Count polling)
   ↓ UART prints "☺A"
   ↓ "PP  init!" (APP  init!)
   ↓ "bl_flash_init!"
0x81E84110  bl_flash_init (MIPS16)
   ↓ FUN_81e889f4 — init
   ↓ FUN_81e870fc(0) — SPI flash driver init
   ↓   FUN_81e87268 — flash probe (sends JEDEC 0x9F)
   ↓ FUN_81e897c4 — lookup flash in linked list
   ↓ if NULL → "Can't find FLASH device!" (but doesn't return!)
   ↓ FUN_81e86fc8(NULL) → CRASH (dereferences NULL)
```

UART output: `☺APP  init!\r\nbl_flash_init!\r\n`

## Key Functions

| Address | Name | Description |
|---|---|---|
| `0x81E84110` | `bl_flash_init` | Flash initialization entry point |
| `0x81E85A1C` | `print_string` | UART string output (like `kprintf`) |
| `0x81E85B14` | `memset` | Memory fill |
| `0x81E846C8` | `malloc` | Memory allocation |
| `0x81E870FC` | `sflash_driver_init` | SPI flash driver registration & probe |
| `0x81E87268` | `sflash_probe` | Flash identification (sends JEDEC ID, matches table) |
| `0x81E87894` | `spi_read_jedec` | Low-level SPI JEDEC read (alternative path) |
| `0x81E889F4` | `spi_controller_init` | SPI controller initialization |
| `0x81E897C4` | `device_list_lookup` | Walk linked list at `_DAT_81e927bc`, match by type |
| `0x81E8CB10` | `get_chip_id` | Read chip ID from `0xB8000002`, return config value |
| `0x81E8DAEC` | `read_cp0_count` | `MFC0 v0, $9` — read CP0 Count register |
| `0x81E8E1B8` | `loader_entry` | MIPS32 loader entry point |

## Supported SPI Flash Chips

From `FUN_81e87268` identification logic:

| JEDEC (LE) | Manufacturer | Type | Example Chip |
|---|---|---|---|
| `0x40EF` | Winbond (0xEF) | 0x40 | W25Q series |
| `0x30EF` | Winbond (0xEF) | 0x30 | W25X series |
| `0x24C2` | Macronix (0xC2) | 0x24 | MX25L |
| `0x20C2` | Macronix (0xC2) | 0x20 | MX25L |
| `0x26BF` | SST/Microchip (0xBF) | 0x26 | SST26VF |
| `0x3037` | AMIC? (0x37) | 0x30 | |
| `0x2037` | AMIC? (0x37) | 0x20 | |

## Key Globals

| Address | Description |
|---|---|
| `_DAT_81e927ac` | Flash JEDEC ID (lower 16 bits) |
| `_DAT_81e927bc` | Head of registered device linked list |
| `_DAT_81e92744` | Current flash device pointer (NULL = not found) |
| `PTR_DAT_81e91f8c` | JEDEC command parameter |
| `PTR_DAT_81e920b0` | SPI command table |
| `PTR_DAT_81e92100` | SPI address mode table |
| `PTR_DAT_81e92128` | SPI config table |
