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


def build(output, version="v1", cross_prefix=None):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", version):
        raise ValueError("version must contain only letters, digits, dot, underscore or dash")
    prefix = find_prefix(cross_prefix)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    elf, binary = output / "app.elf", output / "app.bin"
    flags = ["-EL", "-march=mips32", "-mabi=32", "-msoft-float", "-mno-mips16",
             "-mno-abicalls", "-fno-pic", "-fno-pie", "-G0", "-Os", "-ffreestanding",
             "-fno-builtin", "-fno-stack-protector", "-fno-unwind-tables",
             "-fno-asynchronous-unwind-tables", "-nostdlib", "-nostartfiles",
             # Linux cross GCC may default to PIE even with -fno-pie on the
             # compile step. The bootloader supplies no dynamic ELF loader.
             "-static", "-no-pie",
             "-Wall", "-Wextra", "-Werror", f'-DAPP_VERSION="{version}"']
    command = [prefix + "gcc", *flags, str(HERE / "start.S"), str(HERE / "app.c"),
               "-Wl,--build-id=none", "-Wl,-T," + str(HERE / "link.ld"),
               "-Wl,-Map," + str(output / "app.map"), "-o", str(elf)]
    subprocess.run(command, check=True)
    subprocess.run([prefix + "objcopy", "-O", "binary", str(elf), str(binary)], check=True)
    disassembly = subprocess.check_output([prefix + "objdump", "-d", str(elf)], text=True)
    (output / "app.disasm").write_text(disassembly, encoding="utf-8")
    compiler_version = subprocess.check_output([prefix + "gcc", "--version"], text=True).splitlines()[0]
    manifest = {"version": version, "load_address": "0x80000200", "entry_address": "0x80000200",
                "binary_size": binary.stat().st_size, "compiler": compiler_version,
                "command": command}
    (output / "build.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Built {binary} ({binary.stat().st_size} bytes), entry 0x80000200, {version}")
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cross-prefix", help="compiler prefix, including the final dash")
    parser.add_argument("--version", default="v1")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    build(args.output or ROOT / "build" / "maciej_app" / args.version, args.version, args.cross_prefix)


if __name__ == "__main__":
    main()
