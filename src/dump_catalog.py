"""
The firmware images' sidecars: every image under dumps/ has a `<image>.json`
next to it with the facts about the box and the file -- the device (brand,
model, SoC and its family, demodulator, tuner, flash part, front-panel chip
and pins, IR coding), the image (kind: a dump read from a box or a
manufacturer's update, version, size, SHA-1, chunk layout), where it came from
(URL, site, author, date, whether a login is needed) and what the simulator
makes of it (boots / application / display, the panel's texts) -- and `desc`,
the notes on it as a list of paragraphs.  device.tunerModel, where the tuner
is known, is {"chip", "address" (7-bit, decimal)[, "xtalHz", "ifHz"]}: the
tuner model to put on its I2C bus (tuners.py) and, for an R820T, the
firmware's crystal and IF its frequency is decoded with.
device.demodModel, where the board carries an external demodulator the
simulator models, is {"chip", "address"} (demods.py): loadFile puts it on
the I2C bus.  device.gpioI2c, where the board's tuner or other chips hang on
an I2C bus the firmware bit-bangs over GPIO pins, is {"scl", "sda"} (GPIO
numbers; gpio_i2c.py: its slaves are the I2C devices the hardware masters
reach), and device.gpioPullUps the GPIO numbers of input pins the board
pulls up (status and fault lines that read high when nothing pulls them low;
an input pin nothing models reads 0 otherwise): loadFile attaches both.
device.chipId,
where a board's SoC reads another chip ID than its family's (chips/), is that
ID as a "0x...." string, the evidence in the notes.  tests/test_dump_catalog.py checks
every sidecar against its image and against the code's own tables
(front_panel.PANELS, ir_remote.IR_CODINGS), and tools/dump_table.py renders
them as dumps/README.md.
"""
import hashlib
import json
import os

from simulator import DUMPS_DIR, resolve_dump

IMAGE_SUFFIXES = (".bin", ".abs")
SCHEMA = {                      # the keys every sidecar has, and those of its sections
    "file": None,
    "device": ("brand", "model", "type", "board", "soc", "family", "demod", "tuner", "flash", "panel", "irCoding"),
    "image": ("kind", "version", "date", "size", "sha1", "layout"),
    "source": ("url", "site", "author", "date", "login", "note"),
    "simulator": ("boots", "application", "display", "panelText", "note"),
    "desc": None,
}


def sidecar_path(dump):
    """The sidecar of a dump named the way tests name them (simulator.resolve_dump)."""
    return resolve_dump(dump) + ".json"


def load(dump):
    """The sidecar's contents (a dict), or None when the image has none."""
    path = sidecar_path(dump)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def images():
    """Every firmware image under dumps/ (sorted paths)."""
    out = []
    for root, _dirs, files in os.walk(DUMPS_DIR):
        for name in files:
            if name.lower().endswith(IMAGE_SUFFIXES):
                out.append(os.path.join(root, name))
    return sorted(out, key=str.lower)


def catalog():
    """[(image path, sidecar dict or None)] for every image."""
    return [(path, load(path)) for path in images()]


def sha1_of(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def problems(path, data):
    """What is wrong with an image's sidecar: a list of messages (empty = fine).
    The facts that can be checked against the file are (size, SHA-1 when
    given, the file name); the rest is the schema."""
    out = []
    if data is None:
        return [f"{os.path.relpath(path, DUMPS_DIR)}: no sidecar ({os.path.basename(path)}.json)"]
    rel = os.path.relpath(path, DUMPS_DIR)
    for key, fields in SCHEMA.items():
        if key not in data:
            out.append(f"{rel}: no \"{key}\"")
        elif fields:
            missing = [f for f in fields if f not in data[key]]
            if missing:
                out.append(f"{rel}: \"{key}\" lacks {', '.join(missing)}")
    extra = set(data) - set(SCHEMA)
    if extra:
        out.append(f"{rel}: unknown keys {sorted(extra)}")
    if data.get("file") != os.path.basename(path):
        out.append(f"{rel}: \"file\" is {data.get('file')!r}")
    image = data.get("image") or {}
    if image.get("size") != os.path.getsize(path):
        out.append(f"{rel}: size {image.get('size')} but the file has {os.path.getsize(path)} bytes")
    if image.get("sha1") and image["sha1"] != sha1_of(path):
        out.append(f"{rel}: SHA-1 {image['sha1']} but the file's is {sha1_of(path)}")
    source = data.get("source") or {}
    if not source.get("url") and not source.get("note"):
        out.append(f"{rel}: no source URL and no note saying why")
    desc = data.get("desc")
    if not isinstance(desc, list) or not desc or not all(isinstance(p, str) and p.strip() for p in desc):
        out.append(f"{rel}: \"desc\" must be a non-empty list of paragraphs")
    device = data.get("device") or {}
    if not device.get("soc"):
        out.append(f"{rel}: no SoC")
    chip_id = device.get("chipId")
    if chip_id is not None and not (isinstance(chip_id, str) and len(chip_id) == 6 and chip_id.startswith("0x")
                                    and all(c in "0123456789ABCDEFabcdef" for c in chip_id[2:])):
        out.append(f"{rel}: chipId {chip_id!r} is not a \"0x....\" chip ID")
    demod = device.get("demodModel")
    if demod is not None:
        import demods
        if not (isinstance(demod, dict) and demod.get("chip") in demods.MODELS
                and isinstance(demod.get("address"), int) and 0 < demod["address"] < 0x80):
            out.append(f"{rel}: demodModel {demod!r} is not {{\"chip\": one of {sorted(demods.MODELS)}, "
                       f"\"address\": a 7-bit address}}")
    pin = lambda p: isinstance(p, int) and not isinstance(p, bool) and 0 <= p < 160    # noqa: E731
    bus = device.get("gpioI2c")
    if bus is not None and not (isinstance(bus, dict) and set(bus) == {"scl", "sda"} and all(map(pin, bus.values()))):
        out.append(f"{rel}: gpioI2c {bus!r} is not {{\"scl\": a GPIO number, \"sda\": a GPIO number}}")
    pull_ups = device.get("gpioPullUps")
    if pull_ups is not None and not (isinstance(pull_ups, list) and pull_ups and all(map(pin, pull_ups))):
        out.append(f"{rel}: gpioPullUps {pull_ups!r} is not a list of GPIO numbers")
    return out


def gpio_i2c(dump):
    """(scl, sda) of the I2C bus a board's firmware bit-bangs to its chips
    (device.gpioI2c), or None."""
    given = (((load(dump) or {}).get("device")) or {}).get("gpioI2c")
    return (given["scl"], given["sda"]) if given else None


def gpio_pull_ups(dump):
    """The GPIO numbers of the input pins a board pulls up (device.gpioPullUps)."""
    return list((((load(dump) or {}).get("device")) or {}).get("gpioPullUps") or [])


def demod_model(dump):
    """(chip, 7-bit address) of the demodulator a board's sidecar names
    (device.demodModel), or None."""
    given = (((load(dump) or {}).get("device")) or {}).get("demodModel")
    return (given["chip"], given["address"]) if given else None


def chip_id(dump):
    """The chip ID a board's sidecar gives (device.chipId), or None."""
    given = (((load(dump) or {}).get("device")) or {}).get("chipId")
    return int(given, 16) if given else None
