"""
Every firmware image under dumps/ has a sidecar (dump_catalog.py: <image>.json)
whose facts agree with the file (name, size, SHA-1 when given), which says
where the image came from (a source URL, or a note that the source is not
recorded), has a description, whose front-panel pins and IR coding agree
with the code's own tables (front_panel.PANELS, ir_remote.IR_CODINGS) -- so
the sidecars stay the one place these facts are stated -- and whose
tunerModel, if any, names a model tuners.py has at a valid 7-bit address.  dumps/README.md,
rendered from the sidecars by tools/dump_table.py, must be up to date.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))

import dump_catalog
import dump_table
import front_panel
import ir_remote
import tuners

print("=== Test: every firmware image has a correct sidecar (dump_catalog.py) ===")
failures = []
entries = dump_catalog.catalog()
for path, data in entries:
    failures += dump_catalog.problems(path, data)
    if data is None:
        continue
    rel = os.path.relpath(path, dump_catalog.DUMPS_DIR)
    # the panel pins the decoders use must be the sidecar's
    spec = front_panel.panel_spec(path)
    if spec is front_panel.DEFAULT:         # no entry of its own in PANELS
        spec = None
    panel = data["device"].get("panel")
    if spec and not panel:
        failures.append(f"{rel}: front_panel.PANELS has a panel for it, the sidecar none")
    elif spec:
        for pin in ("scl", "sda", "clk", "dio", "stb"):
            if pin in spec and spec[pin] != panel.get(pin):
                failures.append(f"{rel}: panel {pin} is {panel.get(pin)} in the sidecar, {spec[pin]} in front_panel.PANELS")
    model = data["device"].get("tunerModel")
    if model is not None:
        if model.get("chip") not in tuners.MODELS:
            failures.append(f"{rel}: tunerModel chip {model.get('chip')!r} is not one of tuners.MODELS")
        if not isinstance(model.get("address"), int) or not 0x08 <= model["address"] <= 0x77:
            failures.append(f"{rel}: tunerModel address {model.get('address')!r} is not a 7-bit I2C address")
    coding = ir_remote.coding_for(path)
    if data["device"].get("irCoding") != coding:
        failures.append(f"{rel}: irCoding {data['device'].get('irCoding')!r} in the sidecar, "
                        f"ir_remote.coding_for gives {coding!r}")
readme = os.path.join(dump_catalog.DUMPS_DIR, "README.md")
try:
    with open(readme, encoding="utf-8") as f:
        current = f.read()
except OSError:
    current = ""
if current != dump_table.render(entries):
    failures.append("dumps/README.md is not what tools/dump_table.py renders from the sidecars (run it)")

print(f"{len(entries)} images, {sum(1 for _p, d in entries if d)} sidecars")
for f in failures:
    print(f"  [FAIL] {f}")
if failures:
    print(f"\n[FAIL] {len(failures)} problem(s) in the dump sidecars")
    sys.exit(1)
print("  [PASS] every image has a sidecar that agrees with the file, the code's tables and dumps/README.md")
print("\n[PASS] dump sidecars")
