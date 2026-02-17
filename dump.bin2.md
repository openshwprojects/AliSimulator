# dump.bin — Reverse Engineering Notes

## Chip Info

- SoC: ALi M3329E (or compatible), MIPS16e ASE
- SPI flash controller at `0xB8000000` (base) or `0xB802E000` (for M3329E rev ≥ 5)
- Boot ROM mapped at `0xAFC00000` (KSEG1 uncached)
- RAM at `0x80000000` (KSEG0) / `0xA0000000` (KSEG1)
- Bootloader code at `0x81E80000+` (MIPS16 with MIPS32 islands)

## C Source Reference

Source is from a related chip's SDK: `refs/BootLoader/`

Key SPI flash file: `refs/BootLoader/SRC/LLD/sto/flash/flash_raw_sl_c.c`

## Ghidra → C Function Mapping

### SPI Flash Low-Level (`flash_raw_sl_c.c`)

| Ghidra Address | C Function | Description |
|---|---|---|
| `0x81E87894` | `sflash_get_id()` (line 146) | Detects flash chip via JEDEC ID (0x9F) and Release Power Down (0xAB). Sets `sflash_reg_addr`, checks block protection, removes write protect if set. |
| `0x81E87534` | `sflash_write_enable()` (line 88) | Sends WREN (0x06) or WRDI (0x04) command. param=1 → enable, param=0 → disable. Triggers command by writing 0 to `SYS_FLASH_BASE_ADDR`. |
| `0x81E87464` | `sflash_wait_free()` (line 63) | Polls SPI status register (cmd 0x05) in a loop until bit 0 (WIP/busy) is cleared. Reads status from `SYS_FLASH_BASE_ADDR[0]`. Then restores normal read mode (cmd 0x03 or 0x0B). |
| `0x81E8E124` | `osal_delay()` | Microsecond delay. Called with 10 or 20 (0x14) from wait loops. |
| `0x81E86FC0` | Likely `MUTEX_ENTER()` or flash lock acquire | Called before SPI sequences. |
| `0x81E86FC4` | Likely `MUTEX_LEAVE()` or flash lock release | Called after SPI sequences. |
| `0x81E8CB10` | `sys_ic_get_chip_id()` | Returns chip identification word. |
| `0x81E8CCB8` | `sys_ic_get_rev_id()` | Returns chip revision. |
| `0x81E8D0BC` | Unknown — flash capacity related | Return value checked with `sltiu 0x88`. |
| `0x81E8D3F4` | Unknown — SPI data transfer | Called with `(addr, buf, 1, 0xD8)` → likely sector erase via soft protect. |

### SPI Register Map

```
sflash_reg_addr = 0xB8000000 (default)
                = 0xB802E000 (for M3329E rev >= 5, set via |= 0x8000)

+0x98  SF_INS  — SPI instruction/command register
+0x99  SF_FMT  — Format register (which phases are active)
+0x9A  SF_DUM  — Dummy/config register
+0x9B  SF_CFG  — Configuration register
```

### SF_FMT Bit Flags

```c
SF_HIT_DATA  = 0x01  // Data phase active
SF_HIT_DUMM  = 0x02  // Dummy cycle active
SF_HIT_ADDR  = 0x04  // Address phase active
SF_HIT_CODE  = 0x08  // Command/opcode phase active
SF_CONT_RD   = 0x40  // Continuous read mode
SF_CONT_WR   = 0x80  // Continuous write mode
```

### SPI Command Flow (Hardware Architecture)

The ALi SPI flash controller uses a **dual-interface** design:

1. **Register interface** (`SF_INS`, `SF_FMT`, `SF_DUM` at `0xB802E098-0x9B`)
   - Firmware writes the SPI command opcode to `SF_INS`
   - Firmware sets which SPI phases are active via `SF_FMT`

2. **Memory-mapped interface** (`SYS_FLASH_BASE_ADDR` = `0xAFC00000`)
   - After setting up the command, firmware reads/writes `0xAFC00000` to **trigger** the SPI transaction
   - For reads: the read data appears at `0xAFC00000`
   - For writes: writing to `0xAFC00000` sends the write data

Example — Read JEDEC ID:
```c
write_uint8(SF_FMT, 0x09);   // SF_HIT_CODE | SF_HIT_DATA → send opcode, read data
write_uint8(SF_INS, 0x9F);   // JEDEC Read ID command
result = *(volatile UINT32 *)0xAFC00000;  // Triggers SPI transaction, returns ID
```

Example — Poll busy status:
```c
write_uint8(SF_FMT, 0x09);   // SF_HIT_CODE | SF_HIT_DATA
write_uint8(SF_INS, 0x05);   // Read Status Register
while (*(volatile UINT8 *)0xAFC00000 & 0x01)  // Poll until WIP bit clear
    delay(10);
```

### Global Variables (RAM)

| Address | C Variable | Type | Description |
|---|---|---|---|
| `0x81E926D8` | `sflash_reg_addr` | `UINT32` | SPI register base (0xB8000000 or 0xB802E000) |
| `0x81E926DC` | Saved `SF_INS+SF_FMT` | `UINT16` | Stored format for restore after commands |
| `0x81E927AC` | `sflash_devid` | `UINT16` | Flash device ID (e.g. 0x40EF = Winbond) |
| `0x81E927B0` | `aai_copy_enable` | `UINT16` | 1 if flash supports AAI word program (SST) |
| `0x81E927B2` | Saved `SF_DUM` value | `UINT8` | Restore value for dummy register |
| `0x81E927B4` | Readback buffer | `UINT32` | Used for volatile readback after register writes |
| `0x81E927F0` | `m_EnableSoftProtection` | `UINT32` | Soft protection mode flag |
| `0x81E92714` | `unpro_addr_low` ptr | `UINT32*` | Pointer to unprotected flash region (= 0xAFC00000) |

### Flash ID Detection Logic (`sflash_get_id`)

1. Check chip: if M3329E rev ≥ 5 → `sflash_reg_addr |= 0x8000` (→ `0xB802E000`)
2. Send JEDEC Read ID (0x9F) → read 4 bytes from `0xAFC00000`
3. Send Release Power Down (0xAB) → read 4 bytes from `0xAFC00000`
4. Check ID bytes against known flash chips:
   - `0xBF25xxxx` = SST SST25VFxxx (AAI capable)
   - `0x8C20xxxx` or `0x8C21xxxx` = ESMT (AAI capable)
   - Other → standard page program mode
5. Read status register (0x05) → check protection bits (mask 0x3C)
6. If protected → `sflash_write_enable(1)` + Write Status Register (0x01) with 0x00
7. Wait for completion via `sflash_wait_free()`
8. Restore normal read mode (cmd 0x03)

### Crash Point (Emulator)

The NULL jump at step ~666,176 occurs because `sflash_wait_free()` and `sflash_get_id()` read SPI responses from `0xAFC00000`, which in the emulator returns raw ROM content instead of the SPI controller's response buffer. This causes wrong flash detection and eventually corrupted execution.

### Call Stack at Crash

```
0xAFC007FC  (boot ROM entry)
  └→ 0x81E8E1C0
    └→ 0x81E842D8
      └→ 0x81E84134
        └→ 0x81E85A2E  (memset area)
          └→ 0x81E871B0
            └→ 0x81E8727A
              └→ 0x81E87894  sflash_get_id()
                ├→ 0x81E87534  sflash_write_enable()
                └→ 0x81E87464  sflash_wait_free()
```
