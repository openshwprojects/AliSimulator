#!/usr/bin/env python3
"""Build the RAM application with a MIPS little-endian GCC cross toolchain."""
import argparse
import concurrent.futures
import hashlib
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
                "demo/mouse.c", "demo/console.c", "demo/serial.c", "demo/eth.c",
                "demo/tcp.c", "demo/net.c", "demo/explorer.c", "demo/ftp.c", "demo/smb.c", "demo/nes.c", "demo/gb.c",
                "demo/play.c",
                "demo/image.c", "demo/view.c", "demo/http.c", "demo/web.S", "demo/rf.c", "demo/snd.c",
                "demo/z80.c", "demo/sms.c", "demo/zx.c", "demo/a26.c", "demo/c64.c", "demo/amiga.c", "demo/dos.c",
                "demo/av.c", "demo/avc.c", "demo/mp2.c", "demo/md.c", "demo/zip.c", "demo/tls.c",
                "demo/tls_anchors.S", "demo/ssdp.c", "demo/jpeghw.c", "demo/pce.c", "demo/col.c", "demo/msx.c",
                "demo/ws.c", "demo/snes.c", "demo/neo.c", "demo/gba.c", "demo/a78.c", "demo/lnx.c", "demo/vec.c",
                "demo/o2.c", "demo/intv.c", "demo/ngp.c", "demo/psx.c", "demo/cps.c", "demo/st.c", "demo/s16.c",
                "demo/a8.c", "demo/sv.c", "demo/chip8.c", "demo/channelf.c", "demo/pokemini.c")
BEARSSL = HERE / "bearssl"                      # BearSSL 0.6's files a TLS client needs (bearssl/README.txt)


def _tree_digest(paths):
    h = hashlib.sha256()
    for p in paths:
        h.update(str(p.name).encode("utf-8") + b"\0")
        h.update(p.read_bytes() + b"\0")
    return h.hexdigest()


def build_bearssl(prefix, arch_flags, output):
    """BearSSL's sources (bearssl/src/**/*.c, in name order) compiled into OUTPUT/bearssl/libbearssl.a
    (deterministic: the same files give the same bytes); its path."""
    objects = output / "bearssl"
    objects.mkdir(parents=True, exist_ok=True)
    sources = sorted(BEARSSL.glob("src/**/*.c"), key=lambda p: p.relative_to(BEARSSL).as_posix())
    headers = sorted([*BEARSSL.glob("inc/*.h"), *BEARSSL.glob("src/*.h"), *BEARSSL.glob("shim/*.h")],
                     key=lambda p: p.relative_to(BEARSSL).as_posix())
    flags = [*arch_flags, "-w", "-DBR_USE_URANDOM=0", "-DBR_USE_WIN32_RAND=0", "-DBR_USE_UNIX_TIME=0",
             "-DBR_USE_WIN32_TIME=0", "-DBR_RDRAND=0", "-DBR_64=0", "-DBR_LOMUL=0",
             "-I" + str(BEARSSL / "shim"), "-I" + str(BEARSSL / "inc"), "-I" + str(BEARSSL / "src")]
    library = objects / "libbearssl.a"
    stamp = objects / "bearssl.stamp"
    want_stamp = hashlib.sha256((prefix + "\0" + "\0".join(flags) + "\0" +
                                 _tree_digest([*sources, *headers])).encode("utf-8")).hexdigest()
    if library.exists() and stamp.exists() and stamp.read_text(encoding="utf-8").strip() == want_stamp:
        return library

    def compile_one(src):
        obj = objects / (src.stem + ".o")
        subprocess.run([prefix + "gcc", *flags, "-c", str(src), "-o", str(obj)], check=True, cwd=objects)
        return src.stem + ".o"

    workers = min(16, max(2, os.cpu_count() or 4))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        names = list(pool.map(compile_one, sources))
    if library.exists():
        library.unlink()
    subprocess.run([prefix + "ar", "rcsD", str(library), *names], check=True, cwd=objects)
    stamp.write_text(want_stamp + "\n", encoding="utf-8")
    return library


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
    arch_flags = ["-EL", "-march=mips32", "-mabi=32", "-msoft-float", "-mno-mips16",
                  "-mno-abicalls", "-fno-pic", "-fno-pie", "-G0", "-Os", "-ffreestanding",
                  "-fno-builtin", "-fno-stack-protector", "-fno-unwind-tables",
                  "-fno-asynchronous-unwind-tables"]
    flags = [*arch_flags, "-nostdlib", "-nostartfiles",
             # Linux cross GCC may default to PIE even with -fno-pie on the
             # compile step. The bootloader supplies no dynamic ELF loader.
             "-static", "-no-pie",
             "-Wall", "-Wextra", "-Werror", f'-DAPP_VERSION="{version}"',
             # web.S's and tls_anchors.S's .incbin find their files in the demo's folder
             "-Wa,-I" + str(HERE / "demo")]
    libraries = []
    if "demo/tls.c" in sources:                 # (wget's https://: BearSSL, its headers for tls.c)
        libraries.append(str(build_bearssl(prefix, arch_flags, output)))
        flags += ["-I" + str(BEARSSL / "shim"), "-I" + str(BEARSSL / "inc")]
    for name, value in (defines or {}).items():
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", name):
            raise ValueError(f"invalid define name {name!r}")
        flags.append(f"-D{name}" if value is None else f"-D{name}={value}")
    all_sources = [start, *sources]
    obj_dir = output / "objs"
    obj_dir.mkdir(parents=True, exist_ok=True)
    shared_deps = sorted([*HERE.glob("*.h"), *(HERE / "demo").glob("*.h"), *(HERE / "demo").glob("*.inc"),
                          *(HERE / "demo").glob("*.html"), *(HERE / "demo").glob("*.bin")],
                         key=lambda p: p.relative_to(HERE).as_posix())
    deps_hash = _tree_digest(shared_deps)

    def compile_unit(item):
        idx, rel = item
        src_path = HERE / rel
        obj_path = obj_dir / f"{idx:03d}_{src_path.stem}.o"
        stamp_path = obj_dir / f"{idx:03d}_{src_path.stem}.stamp"
        unit_key = hashlib.sha256((prefix + "\0" + "\0".join(flags) + "\0" + deps_hash + "\0" +
                                   rel + "\0").encode("utf-8") + src_path.read_bytes()).hexdigest()
        if obj_path.exists() and stamp_path.exists() and stamp_path.read_text(encoding="utf-8").strip() == unit_key:
            return str(obj_path)
        subprocess.run([prefix + "gcc", *flags, "-c", str(src_path), "-o", str(obj_path)], check=True)
        stamp_path.write_text(unit_key + "\n", encoding="utf-8")
        return str(obj_path)

    workers = min(16, max(2, os.cpu_count() or 4))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        obj_files = list(pool.map(compile_unit, enumerate(all_sources)))

    command = [prefix + "gcc", *flags, *obj_files, *libraries,
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
