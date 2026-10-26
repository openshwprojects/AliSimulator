"""
Compare two test-suite runs, one per engine: the wall time of each test and,
for the screen regressions, when the application started and when the OSD
became visible (host seconds from the test's start, as screen_regression.py
prints them).

  python tools/engine_compare.py report/results.json report/cpp/results.json
  python tools/engine_compare.py A.json B.json --names unicorn cpp --markdown out.md --json out.json
  python tools/engine_compare.py report/results.json report/cpp/results.json --html report/comparison.html \\
      --link "Unicorn engine=index.html" --link "C++ engine=cpp/index.html"

Each argument is a results.json that run_all_tests.py wrote (report/ for the
Unicorn engine, report/cpp/ for the C++ one); copy them aside between runs.
--html writes a page (the CI publishes it next to the two reports).
"""
import argparse
import html
import json
import math
import os
import re
import sys
from datetime import datetime, timezone

TESTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests")

MILESTONES = (("app", re.compile(r"^\[\s*([\d.]+)s\] application started", re.M)),
              ("osd", re.compile(r"^\[\s*([\d.]+)s\] \d+ GE commands: the OSD is visible", re.M)))


def dump_of(script, tag):
    """The dump a test runs: its dump="..." / FIRMWARE = "..." / first run("...") argument,
    else the runner's tag."""
    try:
        with open(os.path.join(TESTS, script), encoding="utf-8") as f:
            src = f.read()
    except OSError:
        return tag
    m = (re.search(r'\bdump="([^"]+)"', src) or re.search(r'^FIRMWARE = "([^"]+)"', src, re.M)
         or re.search(r'\.run\("([^"]+\.(?:bin|abs|BIN))"', src)
         or re.search(r'"([^"\n]+\.(?:bin|abs|BIN))"', src))
    return os.path.basename(m.group(1)) if m else tag


def load(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    out = {}
    for r in data["results"]:
        tag = next((t["name"] for t in r.get("tags", []) if t["group"] == "dump"), "")
        row = {"elapsed": r["elapsed"], "passed": r["passed"], "na": bool(r.get("not_applicable")),
               "dump": dump_of(r.get("script") or r["name"], tag)}
        for key, rx in MILESTONES:
            m = rx.search(r.get("output") or "")
            row[key] = float(m.group(1)) if m else None
        out[r["name"]] = row
    return data.get("meta", {}), out


def fmt(v, unit="s"):
    return "" if v is None else f"{v:.1f}{unit}" if v < 100 else f"{v:.0f}{unit}"


def ratio(a, b):
    return None if not a or not b else a / b


def status(row):
    return "N/A" if row["na"] else "" if row["passed"] else "FAIL"


LABELS = {"unicorn": "Unicorn", "cpp": "C++"}


def compare(A, B, na, nb, min_s=0.0):
    """The rows of tests both runs have (longest first), the totals, and the
    tests only one run has."""
    rows = []
    for name in sorted(set(A) | set(B)):
        a, b = A.get(name), B.get(name)
        if a is None or b is None:
            continue
        if max(a["elapsed"], b["elapsed"]) < min_s:
            continue
        rows.append({"test": name, "dump": a["dump"] or b["dump"],
                     na: a, nb: b,
                     "speedup": ratio(a["elapsed"], b["elapsed"]),
                     "app_speedup": ratio(a["app"], b["app"]),
                     "osd_speedup": ratio(a["osd"], b["osd"])})
    rows.sort(key=lambda r: -max(r[na]["elapsed"], r[nb]["elapsed"]))
    # totals over the tests that ran on both (a test not applicable on one engine
    # ends at once there: its time says nothing about the engines)
    timed = [r for r in rows if not r[na]["na"] and not r[nb]["na"]]
    totals = {
        "a": sum(r[na]["elapsed"] for r in timed), "b": sum(r[nb]["elapsed"] for r in timed),
        "timed": len(timed),
        "faster_b": sum(1 for r in timed if r["speedup"] and r["speedup"] > 1.05),
        "faster_a": sum(1 for r in timed if r["speedup"] and r["speedup"] < 1 / 1.05),
        "only": sorted((set(A) ^ set(B))),
    }
    return rows, totals


def to_markdown(rows, totals, na, nb, meta_a, meta_b):
    la, lb = LABELS.get(na, na), LABELS.get(nb, nb)
    head = (f"| test | dump | {la} | {lb} | speed-up | app started {la} / {lb} | OSD visible {la} / {lb} |\n"
            f"|---|---|---:|---:|---:|---:|---:|")
    lines = [head]
    for r in rows:
        a, b = r[na], r[nb]
        sa, sb = status(a), status(b)
        speed = "" if r["speedup"] is None or a["na"] or b["na"] else f"{r['speedup']:.2f}x"
        lines.append(
            f"| {r['test']} | {r['dump']} | {fmt(a['elapsed'])} {sa} | {fmt(b['elapsed'])} {sb} | {speed} | "
            f"{fmt(a['app'])} / {fmt(b['app'])} | {fmt(a['osd'])} / {fmt(b['osd'])} |")
    ta, tb = totals["a"], totals["b"]
    overall = f"{ta / tb:.2f}x" if tb else "-"
    summary = (f"\n{totals['timed']} tests ran on both: {la} {ta:.0f} s, {lb} {tb:.0f} s in all (test time "
               f"summed, {overall}); {lb} faster on {totals['faster_b']}, {la} faster on {totals['faster_a']}, "
               f"the rest within 5 %.\nWhole suite, test time summed: {la} {meta_a.get('total_time', 0):.0f} s "
               f"({meta_a.get('note', '')}), {lb} {meta_b.get('total_time', 0):.0f} s ({meta_b.get('note', '')})")
    if totals["only"]:
        summary += "\nIn one run only: " + ", ".join(totals["only"])
    return "\n".join(lines) + "\n" + summary


def _cell_time(row):
    tag = ('<span class="tag na">N/A</span>' if row["na"] else
           "" if row["passed"] else '<span class="tag fail">FAIL</span>')
    return f'<td class="num" data-v="{row["elapsed"]:.3f}">{fmt(row["elapsed"])}{tag}</td>'


def _cell_ms(a, b):
    if a is None and b is None:
        return '<td class="num muted" data-v="">-</td>'
    return (f'<td class="num" data-v="{(a or 0):.3f}">{fmt(a) or "-"} <span class="muted">/</span> '
            f'{fmt(b) or "-"}</td>')


def to_html(rows, totals, na, nb, meta_a, meta_b, links):
    la, lb = LABELS.get(na, na), LABELS.get(nb, nb)
    ta, tb = totals["a"], totals["b"]
    meta = meta_b if meta_b.get("commit") else meta_a
    commit = ""
    if meta.get("commit"):
        short = html.escape(meta["commit"][:8])
        commit = (f' · commit <a href="https://github.com/{html.escape(meta["repo"])}/commit/'
                  f'{html.escape(meta["commit"])}"><code>{short}</code></a>' if meta.get("repo")
                  else f" · commit <code>{short}</code>")
    run = f' · <a href="{html.escape(meta["run_url"])}">CI run</a>' if meta.get("run_url") else ""
    nav = "".join(f'<a href="{html.escape(h)}">{html.escape(l)}</a>' for l, h in links)
    passed_a = sum(1 for r in rows if r[na]["passed"])
    passed_b = sum(1 for r in rows if r[nb]["passed"])
    differ = [r["test"] for r in rows if r[na]["passed"] != r[nb]["passed"]]
    top = max((r["speedup"] for r in rows if r["speedup"] and not r[na]["na"] and not r[nb]["na"]), default=1.0)
    body = []
    for r in rows:
        a, b = r[na], r[nb]
        s = r["speedup"] if not (a["na"] or b["na"]) else None
        if s is None:
            bar = '<td class="num muted" data-v="">-</td>'
        else:
            # log scale: 1x in the middle, the fastest test at the right end
            span = max(math.log(top), math.log(2.0))
            w = min(50.0, abs(math.log(s)) / span * 50.0)
            side = "b" if s >= 1 else "a"
            left = 50.0 if s >= 1 else 50.0 - w
            bar = (f'<td class="num" data-v="{s:.4f}"><div class="spd"><span class="bar {side}" '
                   f'style="left:{left:.1f}%;width:{w:.1f}%"></span><span class="mid"></span></div>'
                   f'<span class="sv {side}">{s:.2f}x</span></td>')
        mark = ' class="differ"' if a["passed"] != b["passed"] else ""
        body.append(f'<tr{mark}><td class="name">{html.escape(r["test"])}</td>'
                    f'<td class="dump">{html.escape(r["dump"] or "")}</td>'
                    f'{_cell_time(a)}{_cell_time(b)}{bar}{_cell_ms(a["app"], b["app"])}'
                    f'{_cell_ms(a["osd"], b["osd"])}</tr>')
    only = ""
    if totals["only"]:
        only = ('<p class="note">In one run only (not compared): ' +
                ", ".join(f"<code>{html.escape(t)}</code>" for t in totals["only"]) + "</p>")
    differ_html = ""
    if differ:
        differ_html = ('<p class="note warn">Passes on one engine and not on the other: ' +
                       ", ".join(f"<code>{html.escape(t)}</code>" for t in differ) + "</p>")
    overall = f"{ta / tb:.1f}x" if tb else "-"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return _PAGE.format(
        la=la, lb=lb, generated=generated, commit=commit, run=run, nav=nav,
        compared=len(rows), timed=totals["timed"], passed_a=passed_a, passed_b=passed_b,
        ta=fmt(ta), tb=fmt(tb), overall=overall, faster_a=totals["faster_a"], faster_b=totals["faster_b"],
        note_a=html.escape(meta_a.get("note", "")), note_b=html.escape(meta_b.get("note", "")),
        rows="\n".join(body), only=only, differ=differ_html)


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Engine Comparison</title>
<style>
  :root {{
    --bg:#f6f7f9; --card:#ffffff; --fg:#1b1f24; --muted:#5b6470; --line:#e3e6ea; --accent:#0969da;
    --pass:#1a7f37; --fail:#cf222e; --failbg:#ffebe9; --warnbg:#fff8c5;
    --a:#8a6d00; --b:#0a5ca8; --abg:#f5e7b0; --bbg:#cfe3fb;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg:#0d1117; --card:#161b22; --fg:#e6edf3; --muted:#8b949e; --line:#30363d; --accent:#4493f8;
      --pass:#3fb950; --fail:#f85149; --failbg:#2b1214; --warnbg:#2e2810;
      --a:#e3b341; --b:#79b8ff; --abg:#4a3b0b; --bbg:#12345a;
    }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
    font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:1360px; margin:0 auto; padding:28px 16px 60px; }}
  h1 {{ margin:0 0 4px; font-size:22px; }}
  .sub {{ color:var(--muted); font-size:13px; margin-bottom:18px; }}
  .sub a, .note a {{ color:var(--accent); text-decoration:none; }}
  .links {{ display:flex; flex-wrap:wrap; gap:8px; margin:-8px 0 18px; }}
  .links a {{ color:var(--accent); text-decoration:none; font-size:13px; font-weight:600;
    border:1px solid var(--line); background:var(--card); border-radius:999px; padding:4px 12px; }}
  .links a:hover {{ border-color:var(--accent); }}
  .summary {{ display:flex; gap:10px; flex-wrap:wrap; margin:0 0 14px; }}
  .stat {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:12px 16px; min-width:120px; }}
  .stat .n {{ font-size:24px; font-weight:700; font-variant-numeric:tabular-nums; }}
  .stat .l {{ font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }}
  .stat.a .n {{ color:var(--a); }} .stat.b .n {{ color:var(--b); }}
  .note {{ color:var(--muted); font-size:13px; margin:0 0 12px; max-width:900px; }}
  .note.warn {{ background:var(--warnbg); color:var(--fg); padding:8px 12px; border-radius:8px; }}
  .tablewrap {{ overflow-x:auto; background:var(--card); border:1px solid var(--line); border-radius:10px; }}
  table {{ border-collapse:collapse; width:100%; font-size:13px; font-variant-numeric:tabular-nums; }}
  th, td {{ padding:7px 10px; border-bottom:1px solid var(--line); text-align:left; white-space:nowrap; }}
  th {{ position:sticky; top:0; background:var(--card); font-size:12px; color:var(--muted);
    text-transform:uppercase; letter-spacing:.03em; cursor:pointer; user-select:none; }}
  th.num, td.num {{ text-align:right; }}
  th:hover {{ color:var(--fg); }}
  th.sorted::after {{ content:" ▾"; }} th.sorted.asc::after {{ content:" ▴"; }}
  tr:last-child td {{ border-bottom:none; }}
  tr.differ td {{ background:var(--failbg); }}
  td.name {{ font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:12px; }}
  td.dump {{ color:var(--muted); max-width:260px; overflow:hidden; text-overflow:ellipsis; }}
  .muted {{ color:var(--muted); }}
  .tag {{ display:inline-block; margin-left:6px; font-size:10px; font-weight:700; padding:0 5px; border-radius:4px; }}
  .tag.fail {{ color:var(--fail); border:1px solid var(--fail); }}
  .tag.na {{ color:var(--muted); border:1px solid var(--line); }}
  .spd {{ position:relative; display:inline-block; vertical-align:middle; width:120px; height:10px;
    background:var(--bg); border-radius:3px; margin-right:8px; }}
  .spd .bar {{ position:absolute; top:0; bottom:0; border-radius:3px; }}
  .spd .bar.a {{ background:var(--a); }} .spd .bar.b {{ background:var(--b); }}
  .spd .mid {{ position:absolute; left:50%; top:-2px; bottom:-2px; width:1px; background:var(--muted); }}
  .sv {{ display:inline-block; min-width:52px; font-weight:600; }}
  .sv.a {{ color:var(--a); }} .sv.b {{ color:var(--b); }}
  @media (max-width:640px) {{ .spd {{ width:60px; }} .stat {{ min-width:0; flex:1 1 40%; }} }}
</style>
</head>
<body>
<div class="wrap">
  <h1>AliSimulator · Engine Comparison</h1>
  <div class="sub">{la} vs {lb} · {generated}{commit}{run}</div>
  <nav class="links">{nav}</nav>
  <div class="summary">
    <div class="stat"><div class="n">{compared}</div><div class="l">Tests compared</div></div>
    <div class="stat"><div class="n">{passed_a} / {passed_b}</div><div class="l">Passed {la} / {lb}</div></div>
    <div class="stat a"><div class="n">{ta}</div><div class="l">{la} test time</div></div>
    <div class="stat b"><div class="n">{tb}</div><div class="l">{lb} test time</div></div>
    <div class="stat b"><div class="n">{overall}</div><div class="l">{lb} speed-up</div></div>
    <div class="stat"><div class="n">{faster_b} / {faster_a}</div><div class="l">Faster on {lb} / {la}</div></div>
  </div>
  <p class="note">Test time summed over the {timed} tests that ran on both engines (a test not applicable on
    one engine is listed but not counted). Speed-up is the {la} time divided by the {lb} time: the bar grows
    right when {lb} is faster, left when {la} is, on a log scale. "App started" and "OSD visible" are the
    host seconds from a screen regression's start to the firmware's application banner and to its first
    drawn screen. The two runs: {la} ({note_a}), {lb} ({note_b}); on CI they run on separate runners at the
    same time, so the times carry the runners' noise. Click a column to sort.</p>
  {differ}
  {only}
  <div class="tablewrap">
  <table id="t">
    <thead><tr>
      <th>Test</th><th>Dump</th><th class="num">{la}</th><th class="num">{lb}</th>
      <th class="num sorted">Speed-up</th><th class="num">App started {la} / {lb}</th>
      <th class="num">OSD visible {la} / {lb}</th>
    </tr></thead>
    <tbody>
{rows}
    </tbody>
  </table>
  </div>
</div>
<script>
(function () {{
  var t = document.getElementById("t"), ths = t.tHead.rows[0].cells, body = t.tBodies[0];
  function key(td, numeric) {{
    if (!numeric) return td.textContent.toLowerCase();
    var v = td.getAttribute("data-v");
    return v === "" || v === null ? null : parseFloat(v);
  }}
  function sortBy(i, asc) {{
    var numeric = ths[i].classList.contains("num");
    var rows = Array.prototype.slice.call(body.rows);
    rows.sort(function (x, y) {{
      var a = key(x.cells[i], numeric), b = key(y.cells[i], numeric);
      if (a === null) return 1; if (b === null) return -1;
      return (a < b ? -1 : a > b ? 1 : 0) * (asc ? 1 : -1);
    }});
    rows.forEach(function (r) {{ body.appendChild(r); }});
    for (var k = 0; k < ths.length; k++) ths[k].classList.remove("sorted", "asc");
    ths[i].classList.add("sorted"); if (asc) ths[i].classList.add("asc");
  }}
  for (var i = 0; i < ths.length; i++) (function (i) {{
    ths[i].addEventListener("click", function () {{
      var asc = ths[i].classList.contains("sorted") ? !ths[i].classList.contains("asc") : !ths[i].classList.contains("num");
      sortBy(i, asc);
    }});
  }})(i);
  sortBy(4, false);
}})();
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--names", nargs=2, default=("unicorn", "cpp"))
    ap.add_argument("--min", type=float, default=0.0, help="leave out tests shorter than this on both (s)")
    ap.add_argument("--markdown", help="write the table there too")
    ap.add_argument("--json", help="write the rows there (for a page)")
    ap.add_argument("--html", help="write a page there (sortable table, summary)")
    ap.add_argument("--link", action="append", default=[], metavar="LABEL=HREF",
                    help="a link in the page's header (repeatable)")
    args = ap.parse_args()
    na, nb = args.names
    meta_a, A = load(args.a)
    meta_b, B = load(args.b)
    rows, totals = compare(A, B, na, nb, args.min)
    text = to_markdown(rows, totals, na, nb, meta_a, meta_b)
    print(text)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"names": [na, nb], "meta": [meta_a, meta_b], "rows": rows}, f, indent=1)
    if args.html:
        links = [tuple(s.split("=", 1)) for s in args.link if "=" in s]
        os.makedirs(os.path.dirname(os.path.abspath(args.html)), exist_ok=True)
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(to_html(rows, totals, na, nb, meta_a, meta_b, links))
        print(f"page written: {args.html}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
