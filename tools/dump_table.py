"""
Render the firmware images' sidecars (src/dump_catalog.py) as dumps/README.md:
a table of the boxes (SoC, tuner, panel, what the simulator makes of them,
source) followed by each image's facts and notes.  Run it after editing a
sidecar; tests/test_dump_catalog.py checks the file is current.

Usage: python tools/dump_table.py          (writes dumps/README.md)
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

import dump_catalog

YES_NO = {True: "yes", False: "no", None: "-"}


def _cell(text):
    return str(text if text is not None else "-").replace("|", "\\|").replace("\n", " ")


def _panel(panel):
    if not panel:
        return "-"
    pins = ", ".join(f"{k.upper()} {panel[k]}" for k in ("scl", "sda", "clk", "dio", "stb") if k in panel)
    return f"{panel.get('chip', '?')} ({pins})" if pins else panel.get("chip", "?")


def _source(source):
    if source.get("url"):
        label = source.get("site") or "link"
        who = f", {source['author']}" if source.get("author") else ""
        return f"[{label}]({source['url']}){who}"
    return "not recorded"


def _short(text, n=60):
    text = text or "-"
    return text if len(text) <= n else text[:n - 3].rstrip() + "..."


def render(entries):
    lines = ["# The firmware images", "",
             "Rendered by `tools/dump_table.py` from the `<image>.json` sidecar next to each image "
             "(`src/dump_catalog.py`; `tests/test_dump_catalog.py` checks them).  Edit the sidecars, "
             "not this file.", "",
             "| Image | Box | SoC | Tuner | Front panel | Boots / app / display | Source |",
             "|---|---|---|---|---|---|---|"]
    for path, data in entries:
        rel = os.path.relpath(path, dump_catalog.DUMPS_DIR).replace("\\", "/")
        if data is None:
            lines.append(f"| `{_cell(rel)}` | (no sidecar) | | | | | |")
            continue
        dev, sim, src = data["device"], data["simulator"], data["source"]
        box = " ".join(x for x in (dev.get("brand"), dev.get("model")) if x) or dev.get("type") or "-"
        status = " / ".join(YES_NO[sim.get(k)] for k in ("boots", "application", "display"))
        lines.append(f"| `{_cell(rel)}` | {_cell(box)} | {_cell(dev.get('soc'))} | {_cell(_short(dev.get('tuner')))} | "
                     f"{_cell(_panel(dev.get('panel')))} | {status} | {_cell(_source(src))} |")
    for path, data in entries:
        if data is None:
            continue
        rel = os.path.relpath(path, dump_catalog.DUMPS_DIR).replace("\\", "/")
        dev, img, src, sim = data["device"], data["image"], data["source"], data["simulator"]
        lines += ["", f"## `{rel}`", ""]
        facts = [("Box", " ".join(x for x in (dev.get("brand"), dev.get("model")) if x) or None),
                 ("Type", dev.get("type")), ("Board", dev.get("board")), ("SoC", f"{dev.get('soc')} ({dev.get('family')})"),
                 ("Demodulator", dev.get("demod")), ("Tuner", dev.get("tuner")), ("Flash", dev.get("flash")),
                 ("Front panel", _panel(dev.get("panel")) if dev.get("panel") else None), ("IR coding", dev.get("irCoding")),
                 ("Image", f"{img.get('kind')}, {img.get('version') or '-'}, {img.get('date') or '-'}, "
                           f"{img.get('size')} bytes" + (f", SHA-1 {img['sha1']}" if img.get("sha1") else "")),
                 ("Layout", img.get("layout")),
                 ("Source", (f"{_source(src)}" + (f" ({src['date']})" if src.get("date") else "")
                             + (" -- login needed" if src.get("login") else "")
                             + (f". {src['note']}" if src.get("note") else ""))),
                 ("Simulator", f"boots {YES_NO[sim.get('boots')]}, application {YES_NO[sim.get('application')]}, "
                               f"display {YES_NO[sim.get('display')]}"
                               + (f", panel {' -> '.join(repr(t) for t in sim['panelText'])}" if sim.get("panelText") else "")
                               + (f". {sim['note']}" if sim.get("note") else ""))]
        for label, value in facts:
            if value:
                lines.append(f"* **{label}:** {value}")
        lines.append("")
        for paragraph in data["desc"]:
            lines += [paragraph, ""]
    return "\n".join(lines).rstrip() + "\n"


if __name__ == "__main__":
    out = os.path.join(dump_catalog.DUMPS_DIR, "README.md")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(render(dump_catalog.catalog()))
    print(f"wrote {out}")
