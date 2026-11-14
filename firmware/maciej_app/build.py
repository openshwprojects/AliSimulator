#!/usr/bin/env python3
"""Build the RAM application with a MIPS little-endian GCC cross toolchain."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def find_prefix(explicit=None):
    if explicit:
        return explicit
    if os.environ.get("MIPS_CROSS_COMPILE"):
        return os.environ["MIPS_CROSS_COMPILE"]
    for prefix in ("mipsel-none-elf-", "mipsel-linux-gnu-", "mipsel-unknown-elf-"):
        compiler = shutil.which(prefix + "gcc")
        if compiler:
            return compiler[:-7] if compiler.endswith("gcc.exe") else compiler[:-3]
    raise SystemExit("MIPS GCC not found. Set MIPS_CROSS_COMPILE or pass --cross-prefix /path/bin/mipsel-none-elf-")


DEFAULT_LOAD_ADDRESS = 0x80000200
# the v4 demo (demo/: command line, TV picture, front panel, remote, USB port)
DEMO_SOURCES = ("demo/main.c", "demo/time.c", "demo/uart.c", "demo/gfx.c",
                "demo/panel.c", "demo/ir.c", "demo/usb.c", "demo/kbd.c", "demo/dog.c", "demo/disk.c",
                "demo/mouse.c", "demo/console.c", "demo/serial.c", "demo/eth.c")


def build(output, version="v1", cross_prefix=None, *, sources=("app.c",),
          load_address=DEFAULT_LOAD_ADDRESS, defines=None, start="start.S"):
    """Compile `start` (start.S; the flash survey's test application uses the
    self-relocating survey_start.S) + `sources` (files in this folder) into
    OUTPUT/app.bin, linked to run at `load_address` (the main code chunk's
    load and entry address; link.ld's own is 0x80000200).  `defines`:
    {name: value} for -D."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", version):
        raise ValueError("version must contain only letters, digits, dot, underscore or dash")
    if load_address & 3 or not 0x80000000 <= load_address < 0xA0000000:
        raise ValueError(f"load address {load_address:#x} must be a word-aligned KSEG0 address")
    prefix = find_prefix(cross_prefix)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    elf, binary = output / "app.elf", output / "app.bin"
    linker_script = HERE / "link.ld"
    if load_address != DEFAULT_LOAD_ADDRESS:
        # the same script with the RAM region (and so _start) moved
        text = linker_script.read_text(encoding="utf-8")
        moved = text.replace("ORIGIN = 0x80000200, LENGTH = 0x007ffe00",
                             f"ORIGIN = {load_address:#010x}, LENGTH = 0x007ffe00")
        if moved == text:
            raise RuntimeError("link.ld no longer has the expected MEMORY line")
        linker_script = output / "link.ld"
        linker_script.write_text(moved, encoding="utf-8")
    flags = ["-EL", "-march=mips32", "-mabi=32", "-msoft-float", "-mno-mips16",
             "-mno-abicalls", "-fno-pic", "-fno-pie", "-G0", "-Os", "-ffreestanding",
             "-fno-builtin", "-fno-stack-protector", "-fno-unwind-tables",
             "-fno-asynchronous-unwind-tables", "-nostdlib", "-nostartfiles",
             # Linux cross GCC may default to PIE even with -fno-pie on the
             # compile step. The bootloader supplies no dynamic ELF loader.
             "-static", "-no-pie",
             "-Wall", "-Wextra", "-Werror", f'-DAPP_VERSION="{version}"']
    for name, value in (defines or {}).items():
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", name):
            raise ValueError(f"invalid define name {name!r}")
        flags.append(f"-D{name}" if value is None else f"-D{name}={value}")
    command = [prefix + "gcc", *flags, str(HERE / start), *[str(HERE / s) for s in sources],
               "-Wl,--build-id=none", "-Wl,-T," + str(linker_script),
               "-Wl,-Map," + str(output / "app.map"), "-o", str(elf)]
    subprocess.run(command, check=True)
    subprocess.run([prefix + "objcopy", "-O", "binary", str(elf), str(binary)], check=True)
    disassembly = subprocess.check_output([prefix + "objdump", "-d", str(elf)], text=True)
    (output / "app.disasm").write_text(disassembly, encoding="utf-8")
    compiler_version = subprocess.check_output([prefix + "gcc", "--version"], text=True).splitlines()[0]
    manifest = {"version": version, "load_address": f"{load_address:#010x}",
                "entry_address": f"{load_address:#010x}", "sources": list(sources),
                "defines": defines or {},
                "binary_size": binary.stat().st_size, "compiler": compiler_version,
                "command": command}
    (output / "build.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Built {binary} ({binary.stat().st_size} bytes), entry {load_address:#010x}, {version}")
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cross-prefix", help="compiler prefix, including the final dash")
    parser.add_argument("--version", default="v1")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--demo", action="store_true",
                        help="build the v4 demo (demo/*.c) instead of the small app.c")
    args = parser.parse_args()
    build(args.output or ROOT / "build" / "maciej_app" / args.version, args.version, args.cross_prefix,
          sources=DEMO_SOURCES if args.demo else ("app.c",))


if __name__ == "__main__":
    main()
