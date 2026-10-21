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
ID as a "0x...." string, the evidence in the notes.  device.otp, where a
board's firmware reads its chip's one-time-programmable memory for something
it must find there, is {"0x<offset>": "<hex bytes>"} (chips/m3821.Otp).
tests/test_dump_catalog.py checks
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


_OVERRIDES = {}                 # resolve_dump(dump) -> dict, JSON path, False (ignore sidecar), or absent
SIDECAR_AUTO = "Auto (<dump>.json)"
SIDECAR_NONE = "None (autodetect only)"


def _override_key(dump):
    return os.path.normcase(os.path.abspath(resolve_dump(dump)))


def set_override(dump, sidecar=None):
    """Override the sidecar `load(dump)` returns: `sidecar` may be a dict, a
    path to a `.json` file, `False` (ignore any sidecar on disk), or `None`
    (restore normal `<dump>.json` lookup)."""
    key = _override_key(dump)
    if sidecar is None:
        _OVERRIDES.pop(key, None)
    else:
        _OVERRIDES[key] = sidecar


def has_override(dump):
    """Whether `dump` currently has an active sidecar override via `set_override`."""
    return _override_key(dump) in _OVERRIDES


def sidecar_path(dump):
    """The sidecar of a dump named the way tests name them (simulator.resolve_dump)."""
    return resolve_dump(dump) + ".json"


_FILE_CACHE = {}                # normcase(abspath(json_path)) -> (mtime_ns, parsed_dict)


def _load_json_file(path):
    k = os.path.normcase(os.path.abspath(path))
    try:
        mtime = os.stat(path).st_mtime_ns
    except OSError:
        _FILE_CACHE.pop(k, None)
        return None
    cached = _FILE_CACHE.get(k)
    if cached is not None and cached[0] == mtime:
        return cached[1]
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    _FILE_CACHE[k] = (mtime, data)
    return data


def load(dump):
    """The sidecar's contents (a dict), or None when the image has none."""
    resolved = resolve_dump(dump)
    key = os.path.normcase(os.path.abspath(resolved))
    if key in _OVERRIDES:
        ov = _OVERRIDES[key]
        if ov is False:
            return None
        if isinstance(ov, dict):
            return ov
        if isinstance(ov, str):
            return _load_json_file(ov)
    return _load_json_file(resolved + ".json")


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


def catalog_entries():
    """Build [(display_label, abs_path, sidecar_dict)] for every image in dumps/."""
    out = []
    for path, sc in catalog():
        rel = os.path.relpath(path, DUMPS_DIR).replace("\\", "/")
        dev = (sc or {}).get("device") or {}
        fam = dev.get("family") or "?"
        cid = dev.get("chipId")
        tag = f"{fam} ({cid})" if cid else fam
        out.append((f"{rel}  [{tag}]", path, sc))
    return out


def resolve_catalog_dump(name, entries=None):
    """Resolve a combobox label, file path, or case-insensitive substring against catalog."""
    entries = entries if entries is not None else catalog_entries()
    for label, path, _sc in entries:
        if name == label:
            return path
    resolved = resolve_dump(name)
    if os.path.exists(resolved):
        return resolved
    needle = name.lower()
    for label, path, _sc in entries:
        if needle in label.lower() or needle in os.path.basename(path).lower():
            return path
    return name


def catalog_label_for(dump, entries=None):
    """Return the catalog display label matching `dump`, or `dump` when outside dumps/."""
    entries = entries if entries is not None else catalog_entries()
    try:
        resolved = _override_key(dump)
        for label, path, _sc in entries:
            if os.path.normcase(os.path.abspath(path)) == resolved:
                return label
    except Exception:
        pass
    return dump


def sidecar_presets(entries=None):
    """Build {display_label: sidecar_arg} for GUI sidecar selector comboboxes."""
    entries = entries if entries is not None else catalog_entries()
    presets = {SIDECAR_AUTO: None, SIDECAR_NONE: False}
    for _label, path, sc in entries:
        rel = os.path.relpath(path, DUMPS_DIR).replace("\\", "/")
        jpath = path + ".json"
        if os.path.isfile(jpath):
            dev = (sc or {}).get("device") or {}
            brand_model = f"{dev.get('brand', '')} {dev.get('model', '')}".strip()
            slabel = f"{brand_model} ({rel})" if brand_model else rel
            presets[slabel] = jpath
    return presets


def apply_sidecar_selection(dump, selection, presets=None):
    """Apply a GUI sidecar selector choice ('Auto...', 'None...', preset label, or path)."""
    sel = (selection or "").strip()
    if not sel or sel == SIDECAR_AUTO:
        set_override(dump, None)
    elif sel == SIDECAR_NONE:
        set_override(dump, False)
    elif presets and sel in presets:
        set_override(dump, presets[sel])
    elif os.path.isfile(sel):
        set_override(dump, sel)
    else:
        set_override(dump, None)


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
    otp_given = device.get("otp")
    if otp_given is not None:
        try:
            ok = isinstance(otp_given, dict) and bool(otp_given) and all(
                k.startswith("0x") and int(k, 16) + len(bytes.fromhex(v)) <= 0x400 and v
                for k, v in otp_given.items())
        except (ValueError, AttributeError, TypeError):
            ok = False
        if not ok:
            out.append(f"{rel}: otp is not {{\"0x<offset>\": \"<hex bytes>\"}} within 1 KB")
    return out


def _device(dump):
    return ((load(dump) or {}).get("device")) or {}


def otp(dump):
    """{offset: bytes} of a board's one-time-programmable memory the sidecar
    gives (device.otp), or None."""
    given = _device(dump).get("otp")
    return {int(k, 16): bytes.fromhex(v) for k, v in given.items()} if given else None


def gpio_i2c(dump):
    """(scl, sda) of the I2C bus a board's firmware bit-bangs to its chips
    (device.gpioI2c), or None."""
    given = _device(dump).get("gpioI2c")
    return (given["scl"], given["sda"]) if given else None


def gpio_pull_ups(dump):
    """The GPIO numbers of the input pins a board pulls up (device.gpioPullUps)."""
    return list(_device(dump).get("gpioPullUps") or [])


def demod_model(dump):
    """(chip, 7-bit address) of the demodulator a board's sidecar names
    (device.demodModel), or None."""
    given = _device(dump).get("demodModel")
    return (given["chip"], given["address"]) if given else None


def chip_id(dump):
    """The chip ID a board's sidecar gives (device.chipId), or None."""
    given = _device(dump).get("chipId")
    return int(given, 16) if given else None


def tuner_model(dump):
    """The tuner model dict a board's sidecar gives (device.tunerModel), or None."""
    return _device(dump).get("tunerModel")


def ir_coding(dump):
    """The IR coding string a board's sidecar gives (device.irCoding), or None."""
    return _device(dump).get("irCoding")
