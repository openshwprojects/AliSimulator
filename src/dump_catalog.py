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
firmware's crystal and IF its frequency is decoded with.  tests/test_dump_catalog.py checks
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
    return out
