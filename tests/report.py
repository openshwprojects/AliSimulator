"""Render the self-test results as one self-contained HTML page (report/index.html).

run_all_tests.py collects, for every test script it ran: pass / fail, wall
time, the script's docstring, the [PASS] / [FAIL] lines it printed (its
assertions), its whole output, and the images it attached through
report_artifacts.py -- screen captures as PNG files and front-panel LED
displays as segment bytes.  This module turns that into a single HTML file
(inline CSS / JS, the PNGs embedded as data URIs, the LED displays drawn as
inline SVG), so it reads the same opened from disk, as a CI artifact and
published to GitHub Pages.

The page starts with the featured runs, opened: one full run per box (a test
whose script declares FEATURED), titled "<box> with <SoC> + <panel chip> +
<tuner>" over what the run shows.  Its screens come first, each capture on
its own row with a column on its right: the tuner's frequency above the
front-panel display, both as they were when the screen was captured (a click
shows the screen at full size); then its assertions, with its description
and output folded.  Every other test follows as a closed card behind tag
filters, its description cut to a few lines.

Modelled on the BekenSimulator report (tests/report.py there): summary cards,
tag filters, one expandable card per test.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import base64
import html
import re
from datetime import datetime, timezone

from front_panel import SEG_POLYS          # the 7-segment geometry, drawn here as SVG and by tv_gui.py

TITLE = "AliSimulator · Self-Test Report"
DESC_LINES = 3          # a closed card's description shows this many lines until "more"


def _fmt_secs(s):
    return "%.0fs" % s if s >= 1 else "%.1fs" % s


def _fmt_compact(secs):
    if secs >= 60:
        return "%dm %02ds" % (int(secs // 60), int(round(secs % 60)))
    return "%.1fs" % secs


def _fmt_total(secs):
    if secs >= 60:
        m = int(secs // 60)
        return "%d minute%s %.2f seconds" % (m, "" if m == 1 else "s", secs - m * 60)
    return "%.2f seconds" % secs


def _highlight(text, checks):
    """HTML-escape the log and colour the [PASS] / [FAIL] lines in it."""
    out = []
    for line in html.escape(text).split("\n"):
        if "[PASS]" in line:
            out.append('<span class="lpass">%s</span>' % line)
        elif "[FAIL]" in line:
            out.append('<span class="lfail">%s</span>' % line)
        else:
            out.append(line)
    return "\n".join(out)


def panel_svg(digits, scale=1.0):
    """Inline SVG of a 4-digit 7-segment display from its segment bytes."""
    parts = []
    for d, v in enumerate(list(digits)[:4]):
        ox = 10 + d * 34
        for s, poly in SEG_POLYS.items():
            pts = " ".join("%d,%d" % (ox + x, 6 + y) for x, y in poly)
            parts.append('<polygon points="%s" class="%s"/>' % (pts, "on" if (v >> s) & 1 else "off"))
        parts.append('<circle cx="%d" cy="%d" r="2.2" class="%s"/>'
                     % (ox + 27, 6 + 43, "on" if (v >> 7) & 1 else "off"))
    w, h = 4 * 34 + 12, 58
    return ('<svg class="seg" viewBox="0 0 %d %d" width="%d" height="%d" '
            'xmlns="http://www.w3.org/2000/svg"><rect width="%d" height="%d" rx="6" class="bg"/>%s</svg>'
            % (w, h, int(w * scale), int(h * scale), w, h, "".join(parts)))


def _data_uri(path):
    with open(path, "rb") as f:
        return "data:image/png;base64," + base64.b64encode(f.read()).decode("ascii")


def _image_figure(img):
    """A screen capture (the PNG embedded), or a placeholder for a missing file."""
    cap = html.escape(img.get("caption") or os.path.basename(img["path"]))
    if img.get("missing"):
        return ('<figure class="shot missing"><div class="nofile">file not found</div>'
                '<figcaption>%s<br><code>%s</code></figcaption></figure>'
                % (cap, html.escape(os.path.basename(img["path"]))))
    try:
        src = _data_uri(img["path"])
    except OSError:
        return ('<figure class="shot missing"><div class="nofile">unreadable</div>'
                '<figcaption>%s</figcaption></figure>' % cap)
    return ('<figure class="shot"><img src="%s" alt="%s" loading="lazy"><figcaption>%s</figcaption></figure>'
            % (src, cap, cap))


def _panel_figure(p):
    """A front-panel LED display (SVG) with its decoded text."""
    text = html.escape(p.get("text") or "")
    cap = html.escape(p.get("caption") or "front panel")
    return ('<figure class="shot panel">%s<figcaption>%s%s</figcaption></figure>'
            % (panel_svg(p["digits"], 2.0), cap, (' <code class="ptext">[%s]</code>' % text) if text else ""))


def _side_html(img, panel=None):
    """The column right of a capture: what the tuner was tuned to when it was
    taken, above the front-panel display at that moment (the image's own, or
    a display the test reported right after it); empty when neither applies."""
    parts = []
    if img.get("tuner"):
        # tuners.describe(): "<model>: <frequency or state>"; the model is the
        # protocol's (an MxL608 is driven as an MxL603), so it goes in the tooltip
        model, _, value = img["tuner"].partition(": ")
        if not value:
            model, value = "", model
        parts.append('<div class="tuner" title="what the tuner%s was tuned to when the screen was captured">'
                     '<span class="tchip">tuner</span><span class="tval">%s</span></div>'
                     % (" (the %s model)" % html.escape(model) if model else "", html.escape(value)))
    panel = img.get("panel") or panel
    if panel:
        parts.append(_panel_figure(panel))
    return '<div class="side">%s</div>' % "".join(parts) if parts else ""


def _renders_html(r):
    """The test's renders, one row each: a screen capture and, in a column on
    its right, the tuner's frequency above the front-panel display -- both as
    they were when the screen was captured (a box without a display has none;
    an older test reports a display right after its capture instead).  A
    display reported on its own gets its own row.  The runner numbers both
    kinds in the order the test printed them ("order")."""
    items = [("image", i) for i in r.get("images", [])] + [("panel", p) for p in r.get("panels", [])]
    items.sort(key=lambda kind_item: kind_item[1].get("order", 0))
    rows = []
    i = 0
    while i < len(items):
        kind, item = items[i]
        if kind == "panel":
            rows.append('<div class="render">%s</div>' % _panel_figure(item))
        else:
            following = None
            if not item.get("panel") and i + 1 < len(items) and items[i + 1][0] == "panel":
                i += 1
                following = items[i][1]
            rows.append('<div class="render">%s%s</div>' % (_image_figure(item), _side_html(item, following)))
        i += 1
    return '<div class="renders">%s</div>' % "".join(rows)


def _tag_class(tag):
    return "tag " + {"dump": "dump", "kind": "kind", "data": "data"}.get(tag.get("group", "feature"), "feat")


def _tags_html(r):
    return "".join('<span class="%s">%s</span>' % (_tag_class(t), html.escape(t["name"]))
                   for t in r.get("tags", []))


def _status(r):
    """(card class, status badge) of a result."""
    if r["passed"]:
        return "pass", "PASS"
    return "fail", "CRASH" if r.get("crashed") else "FAIL"


def _checks_html(r):
    """The test's [PASS] / [FAIL] lines as a list."""
    checks = r.get("checks") or []
    if not checks:
        return ('<li class="none">no [PASS] / [FAIL] lines; the verdict is the exit code (%s)</li>'
                % r.get("exit_code", 0))
    return "".join('<li class="%s"><span class="chk">%s</span>%s</li>'
                   % ("found" if c["ok"] else "missing", "✓" if c["ok"] else "✗", html.escape(c["text"]))
                   for c in checks)


def _log_html(r, title="Output"):
    """The test's whole output, with a Copy button."""
    return ('<div class="stitle logbar"><span>%s</span><button class="copy-btn" type="button">Copy</button></div>'
            '<pre class="log">%s</pre>' % (title, _highlight(r.get("output", ""), r.get("checks") or [])))


def _desc_html(text):
    """The description; a long one shows its first DESC_LINES lines and a
    switch for the rest."""
    text = text or "(no description)"
    if text.count("\n") < DESC_LINES and len(text) <= 80 * DESC_LINES:
        return '<p class="desc">%s</p>' % html.escape(text)
    return '<p class="desc clamp">%s</p><button class="more-btn" type="button">more</button>' % html.escape(text)


def _timed(r):
    return ' <span class="warn">(timed out)</span>' if r.get("timed_out") else ""


def _test_card(r):
    status_cls, status_txt = _status(r)
    n_img = len(r.get("images", [])) + len(r.get("panels", []))
    first = next((i for i in r.get("images", []) if not i.get("missing")), None)
    thumb = ""
    if first:
        try:
            thumb = '<img class="thumb" src="%s" alt="">' % _data_uri(first["path"])
        except OSError:
            thumb = ""
    elif r.get("panels"):
        thumb = '<span class="thumb-svg">%s</span>' % panel_svg(r["panels"][-1]["digits"], 0.55)
    return """
    <details class="card {status_cls}" data-tags="{tagdata}">
      <summary>
        <span class="dot"></span>
        <span class="head">
          <span class="row1">
            <span class="title">{name}</span>
            <span class="badges">
              <span class="badge status">{status_txt}</span>
              <span class="badge">{secs}{timed}</span>
              <span class="badge muted">{imgs}</span>
            </span>
          </span>
          <span class="tags">{tags}</span>
        </span>
        {thumb}
      </summary>
      <div class="body">
        {desc}
        <div class="meta"><span class="args"><code>python tests/{script}</code></span></div>
        <div class="checks"><div class="stitle">Assertions</div><ul>{checks}</ul></div>
        {renders}
        {log}
      </div>
    </details>
    """.format(
        status_cls=status_cls, status_txt=status_txt,
        name=html.escape(r["name"]), secs=_fmt_secs(r["elapsed"]), timed=_timed(r),
        imgs=("%d image%s" % (n_img, "" if n_img == 1 else "s")) if n_img else "",
        tags=_tags_html(r),
        tagdata=html.escape("|".join("%s:%s" % (t.get("group", "feature"), t["name"]) for t in r.get("tags", []))),
        thumb=thumb,
        desc=_desc_html(r.get("description")),
        script=html.escape(r["script"]),
        checks=_checks_html(r),
        renders=('<div class="stitle">Images (%d)</div>%s' % (n_img, _renders_html(r))) if n_img else "",
        log=_log_html(r),
    )


def featured_title(f):
    """A featured run's title: "<device> with <chip> + <chip> ..."."""
    chips = " + ".join(f.get("chips") or [])
    return f["device"] + (" with " + chips if chips else "")


def featured_subtitle(f):
    """What a featured run shows, as one line: "Boots to screen, reacts to remote"."""
    text = ", ".join(f.get("shows") or [])
    return text[:1].upper() + text[1:]


def _anchor(r):
    return "run-" + re.sub(r"[^A-Za-z0-9_-]", "-", os.path.splitext(r["script"])[0])


def _featured_card(r):
    """A featured run, opened: the box and its chips over what the run shows,
    its screens, its assertions, then its description and output folded."""
    f = r["featured"]
    status_cls, status_txt = _status(r)
    chips = " + ".join(html.escape(c) for c in f.get("chips") or [])
    has_renders = r.get("images") or r.get("panels")
    return """
    <details class="card featured {status_cls}" id="{anchor}" open>
      <summary>
        <span class="dot"></span>
        <span class="head">
          <span class="row1">
            <span class="ftitle"><span class="dev">{device}</span>{chips}</span>
            <span class="badges">
              <span class="badge status">{status_txt}</span>
              <span class="badge">{secs}{timed}</span>
            </span>
          </span>
          <span class="fsub">{subtitle}</span>
        </span>
      </summary>
      <div class="body">
        {renders}
        <div class="checks"><div class="stitle">Assertions</div><ul>{checks}</ul></div>
        <details class="fold"><summary>About this run</summary>
          <p class="desc">{desc}</p>
          <div class="meta"><span class="args"><code>python tests/{script}</code></span><span class="tags">{tags}</span></div>
        </details>
        <details class="fold"><summary>Output</summary>{log}</details>
      </div>
    </details>
    """.format(
        status_cls=status_cls, status_txt=status_txt, anchor=_anchor(r),
        device=html.escape(f["device"]),
        chips=(' <span class="with">with</span> <span class="chips">%s</span>' % chips) if chips else "",
        subtitle=html.escape(featured_subtitle(f)),
        secs=_fmt_compact(r["elapsed"]), timed=_timed(r),
        renders=_renders_html(r) if has_renders else
        '<p class="empty">No screen was captured; see the output.</p>',
        checks=_checks_html(r),
        desc=html.escape(r.get("description") or "(no description)"),
        script=html.escape(r["script"]),
        tags=_tags_html(r),
        log=_log_html(r, ""),
    )


def _featured_section(featured, more):
    """The featured runs with an index of their boxes (and, when `more`, a
    link down to the other tests)."""
    index = "".join('<a href="#%s" class="%s"><span class="fdot"></span>%s</a>'
                    % (_anchor(r), _status(r)[0], html.escape(r["featured"]["device"])) for r in featured)
    if more:
        index += '<a href="#tests" class="more">Other tests ↓</a>'
    return """
  <section class="group featured-group">
    <h2 class="gtitle">Featured runs <span class="gcount">{count}</span></h2>
    <p class="ghint">One full run per box. Each row is a screen its firmware drew, with the tuner above the
      front-panel display as they were at that moment; click a screen to see it at full size.</p>
    <nav class="findex">{index}</nav>
    {cards}
  </section>""".format(count=len(featured), index=index, cards="".join(_featured_card(r) for r in featured))


def _filters_html(results):
    order = ["dump", "kind", "data"]
    groups = {}
    for r in results:
        for t in r.get("tags", []):
            g = t.get("group", "feature")
            groups.setdefault(g, {}).setdefault(t["name"], 0)
            groups[g][t["name"]] += 1
    if not groups:
        return ""
    blocks = []
    for g in order + sorted(set(groups) - set(order)):
        if g not in groups:
            continue
        chips = "".join(
            '<button class="fchip %s" type="button" data-group="%s" data-tag="%s">%s<span class="fcount">%d</span></button>'
            % (_tag_class({"name": n, "group": g}).replace("tag ", ""), html.escape(g), html.escape(n), html.escape(n), c)
            for n, c in sorted(groups[g].items(), key=lambda kv: (-kv[1], kv[0])))
        blocks.append('<div class="fgroup"><span class="flabel">%s</span>%s</div>' % (html.escape(g), chips))
    return """
  <div class="filters">
    <div class="fhead">
      <span class="fhint">Filter by tag - none selected shows everything. Two tags in one row widen; tags across rows narrow.</span>
      <button class="fclear" type="button" hidden>Clear all</button>
    </div>
    %s
    <div class="fstatus" hidden></div>
  </div>""" % "".join(blocks)


def _others_section(others, title):
    return """
  <section class="group others" id="tests">
    <h2 class="gtitle">{title} <span class="gcount">{count}</span></h2>
    {filters}
    {cards}
  </section>""".format(title=title, count=len(others), filters=_filters_html(others),
                       cards="".join(_test_card(r) for r in others))


def generate(results, meta, out_path):
    """Render results to a single HTML file at out_path.  Returns out_path."""
    passed = sum(1 for r in results if r["passed"])
    failed = len(results) - passed
    commit_html = ""
    if meta.get("commit"):
        short = meta["commit"][:8]
        if meta.get("repo"):
            commit_html = 'commit <a href="https://github.com/%s/commit/%s"><code>%s</code></a>' % (
                html.escape(meta["repo"]), html.escape(meta["commit"]), short)
        else:
            commit_html = "commit <code>%s</code>" % short
    run_html = ' · <a href="%s">CI run</a>' % html.escape(meta["run_url"]) if meta.get("run_url") else ""
    generated_ms = ""
    m = re.match(r"(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d) UTC", meta.get("generated_at", "") or "")
    if m:
        generated_ms = str(int(datetime(*(int(x) for x in m.groups()), tzinfo=timezone.utc).timestamp() * 1000))
    dumps = sorted({t["name"] for r in results for t in r.get("tags", []) if t.get("group") == "dump"})
    n_img = sum(len(r.get("images", [])) + len(r.get("panels", [])) for r in results)
    # the featured runs first, by box; then every other test in the runner's order
    featured = sorted((r for r in results if r.get("featured")), key=lambda r: featured_title(r["featured"]).lower())
    others = [r for r in results if not r.get("featured")]
    sections = (_featured_section(featured, bool(others)) if featured else "") + \
        (_others_section(others, "Other tests" if featured else "Tests") if others else "")
    page = _PAGE.format(
        title=html.escape(TITLE),
        passed=passed, failed=failed, total=len(results),
        runtime=_fmt_compact(meta.get("total_time", 0)),
        images=n_img,
        dumps=len(dumps), dumps_list=html.escape(", ".join(dumps)),
        total_time=_fmt_total(meta.get("total_time", 0)),
        generated=html.escape(meta.get("generated_at", "")), generated_ms=generated_ms,
        commit_html=commit_html, run_html=run_html,
        note=html.escape(meta.get("note", "")),
        sections=sections,
        desc_lines=DESC_LINES,
        script=_SCRIPT,
    )
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)
    return out_path


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{
    --bg:#f6f7f9; --card:#ffffff; --fg:#1b1f24; --muted:#5b6470; --line:#e3e6ea;
    --pass:#1a7f37; --fail:#cf222e; --passbg:#dafbe1; --failbg:#ffebe9; --accent:#0969da;
    --t-dump:#0a5ca8; --t-dump-bg:#dceafb; --t-kind:#5a3ea8; --t-kind-bg:#ece7fb;
    --seg-on:#ff3b30; --seg-off:#2a1210; --seg-bg:#111;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg:#0d1117; --card:#161b22; --fg:#e6edf3; --muted:#8b949e; --line:#30363d;
      --pass:#3fb950; --fail:#f85149; --passbg:#12261a; --failbg:#2b1214; --accent:#4493f8;
      --t-dump:#79b8ff; --t-dump-bg:#12283f; --t-kind:#b39dfb; --t-kind-bg:#2a2340;
    }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
    font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:1360px; margin:0 auto; padding:28px 18px 60px; }}
  header h1 {{ margin:0 0 4px; font-size:22px; }}
  .sub {{ color:var(--muted); font-size:13px; margin-bottom:18px; }}
  .sub a {{ color:var(--accent); text-decoration:none; }}
  .ago {{ font-style:italic; opacity:.8; white-space:nowrap; }}
  .note {{ color:var(--muted); font-size:13px; margin:-10px 0 16px; }}
  .summary {{ display:flex; gap:10px; flex-wrap:wrap; margin:0 0 6px; }}
  .stat {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:12px 16px; min-width:96px; }}
  .stat .n {{ font-size:24px; font-weight:700; }}
  .stat .l {{ font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }}
  .stat.pass .n {{ color:var(--pass); }} .stat.fail .n {{ color:var(--fail); }}
  .group {{ margin:28px 0 0; }}
  .gtitle {{ font-size:18px; margin:0 0 4px; display:flex; align-items:center; gap:8px; }}
  .gcount {{ font-size:12px; font-weight:600; color:var(--muted); background:var(--card); border:1px solid var(--line);
    border-radius:20px; padding:0 8px; }}
  .ghint {{ color:var(--muted); font-size:13px; margin:0 0 10px; }}
  .findex {{ display:flex; flex-wrap:wrap; gap:6px; margin:0 0 4px; }}
  .findex a {{ font-size:12.5px; padding:2px 10px; border-radius:20px; border:1px solid var(--line); background:var(--card);
    color:var(--fg); text-decoration:none; display:inline-flex; gap:6px; align-items:center; white-space:nowrap; }}
  .findex a:hover {{ border-color:var(--accent); color:var(--accent); }}
  .fdot {{ width:7px; height:7px; border-radius:50%; background:var(--pass); flex:0 0 auto; }}
  .findex a.fail .fdot {{ background:var(--fail); }}
  .findex a.more {{ color:var(--muted); background:transparent; }}
  .filters {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:12px 14px; margin:10px 0 16px; }}
  .fhead {{ display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:8px; }}
  .fhint {{ font-size:12px; color:var(--muted); }}
  .fclear {{ font-size:12px; padding:3px 10px; border-radius:6px; border:1px solid var(--line); background:var(--bg); color:var(--fg); cursor:pointer; }}
  .fgroup {{ display:flex; align-items:baseline; gap:6px; flex-wrap:wrap; margin:5px 0; }}
  .flabel {{ font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); width:56px; flex:0 0 auto; }}
  .fchip {{ font-size:11.5px; padding:2px 8px; border-radius:20px; cursor:pointer; border:1px solid var(--line);
    background:var(--bg); color:var(--muted); display:inline-flex; gap:6px; align-items:center; }}
  .fchip:hover {{ color:var(--fg); border-color:var(--accent); }}
  .fchip.on {{ background:var(--accent); border-color:var(--accent); color:#fff; font-weight:700; }}
  .fchip.zero {{ opacity:.35; }}
  .fcount {{ font-size:10px; opacity:.8; }}
  .fstatus {{ margin-top:8px; font-size:12px; color:var(--muted); }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:10px; margin:10px 0; overflow:hidden; }}
  .card.fail {{ border-color:var(--fail); }}
  .card.featured {{ margin:14px 0; scroll-margin-top:12px; }}
  .group.others {{ scroll-margin-top:12px; }}
  summary {{ display:flex; align-items:center; gap:10px; padding:12px 16px; cursor:pointer; list-style:none; }}
  summary::-webkit-details-marker {{ display:none; }}
  .card.featured > summary {{ align-items:flex-start; padding:14px 18px; }}
  .dot {{ width:10px; height:10px; border-radius:50%; flex:0 0 auto; background:var(--pass); }}
  .card.fail .dot {{ background:var(--fail); }}
  .card.featured .dot {{ margin-top:8px; }}
  .head {{ flex:1; display:flex; flex-direction:column; gap:6px; min-width:0; }}
  .card.featured .head {{ gap:3px; }}
  .row1 {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .title {{ font-weight:600; flex:1; min-width:0; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:14px; }}
  .ftitle {{ flex:1; min-width:0; font-size:18px; line-height:1.35; }}
  .ftitle .dev {{ font-weight:700; }}
  .ftitle .with {{ color:var(--muted); }}
  .ftitle .chips {{ font-weight:600; }}
  .fsub {{ font-size:14.5px; color:var(--muted); }}
  .thumb {{ height:44px; width:78px; object-fit:cover; border-radius:5px; border:1px solid var(--line); background:#000; flex:0 0 auto; }}
  .thumb-svg {{ flex:0 0 auto; display:inline-flex; }}
  .tags {{ display:flex; gap:5px; flex-wrap:wrap; }}
  .tag {{ font-size:10.5px; line-height:1.5; padding:1px 7px; border-radius:4px; font-weight:700; letter-spacing:.02em;
    white-space:nowrap; border:1px solid transparent; }}
  .tag.dump {{ background:var(--t-dump-bg); color:var(--t-dump); }}
  .tag.kind {{ background:var(--t-kind-bg); color:var(--t-kind); }}
  .tag.data {{ background:transparent; color:var(--accent); border-color:var(--accent); }}
  .tag.feat {{ background:var(--bg); color:var(--muted); border-color:var(--line); }}
  .badges {{ display:flex; gap:6px; align-items:center; flex-wrap:wrap; }}
  .badge {{ font-size:12px; padding:2px 8px; border-radius:20px; background:var(--bg); border:1px solid var(--line);
    color:var(--muted); white-space:nowrap; }}
  .badge.status {{ font-weight:700; }}
  .badge:empty {{ display:none; }}
  .card.pass .badge.status {{ background:var(--passbg); color:var(--pass); border-color:transparent; }}
  .card.fail .badge.status {{ background:var(--failbg); color:var(--fail); border-color:transparent; }}
  .warn {{ color:var(--fail); }}
  .body {{ padding:2px 16px 16px; border-top:1px solid var(--line); }}
  .card.featured > .body {{ padding:14px 18px 14px; }}
  .desc {{ color:var(--fg); margin:12px 0; white-space:pre-line; }}
  .desc.clamp {{ display:-webkit-box; -webkit-box-orient:vertical; -webkit-line-clamp:{desc_lines}; line-clamp:{desc_lines};
    overflow:hidden; margin-bottom:2px; }}
  .more-btn {{ border:0; background:none; padding:0; margin:0 0 12px; color:var(--accent); cursor:pointer; font-size:13px; }}
  .meta {{ display:flex; gap:14px; flex-wrap:wrap; align-items:center; margin-bottom:12px; }}
  .args code {{ color:var(--muted); font-size:12px; }}
  .stitle {{ font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); margin:14px 0 6px; }}
  .logbar {{ display:flex; align-items:center; justify-content:space-between; margin-top:16px; }}
  details.fold {{ margin-top:12px; border-top:1px solid var(--line); }}
  details.fold > summary {{ display:block; padding:8px 0 0; font-size:12px; text-transform:uppercase;
    letter-spacing:.04em; color:var(--muted); }}
  details.fold > summary::before {{ content:"▸ "; }}
  details.fold[open] > summary::before {{ content:"▾ "; }}
  details.fold > summary:hover {{ color:var(--accent); }}
  details.fold .logbar {{ margin-top:6px; }}
  .checks ul {{ list-style:none; margin:0; padding:0; }}
  .checks li {{ display:flex; gap:8px; align-items:baseline; padding:2px 0; font-size:13.5px; }}
  .checks li.none {{ color:var(--muted); font-style:italic; }}
  .checks .chk {{ font-weight:700; width:14px; flex:0 0 auto; }}
  .checks li.found .chk {{ color:var(--pass); }}
  .checks li.missing {{ color:var(--fail); }}
  .checks li.missing .chk {{ color:var(--fail); }}
  .copy-btn {{ font-size:12px; padding:3px 10px; border-radius:6px; border:1px solid var(--line); background:var(--card);
    color:var(--fg); cursor:pointer; }}
  .copy-btn:hover {{ border-color:var(--accent); color:var(--accent); }}
  .copy-btn.copied {{ color:var(--pass); border-color:var(--pass); }}
  code {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12.5px; }}
  pre.log {{ background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:12px; overflow:auto;
    max-height:460px; font-size:12px; line-height:1.45; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    white-space:pre-wrap; word-break:break-word; }}
  .lpass {{ color:var(--pass); font-weight:700; }}
  .lfail {{ color:var(--fail); font-weight:700; }}
  .empty {{ color:var(--muted); font-size:13px; }}
  .renders {{ display:flex; flex-direction:column; gap:14px; }}
  .render {{ display:flex; gap:16px; align-items:center; flex-wrap:wrap; }}
  .shot {{ margin:0; background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:8px;
    flex:0 1 676px; min-width:0; }}
  .shot img {{ display:block; width:100%; height:auto; border-radius:4px; background:#000; cursor:zoom-in; }}
  .shot figcaption {{ font-size:12px; color:var(--muted); margin-top:6px; }}
  .shot.panel {{ flex:0 0 auto; display:flex; flex-direction:column; align-items:center; max-width:100%; }}
  .shot.panel svg {{ max-width:100%; height:auto; }}
  .side {{ flex:0 1 auto; min-width:0; max-width:100%; display:flex; flex-direction:column; align-items:stretch; gap:10px; }}
  .tuner {{ background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:8px 12px;
    text-align:center; white-space:nowrap; }}
  .tuner .tchip {{ display:block; font-size:11px; color:var(--muted); letter-spacing:.03em; }}
  .tuner .tval {{ display:block; font:700 17px/1.35 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    color:var(--fg); }}
  .shot.missing {{ flex:0 0 auto; }}
  .shot.missing .nofile {{ width:200px; height:60px; display:flex; align-items:center; justify-content:center;
    color:var(--fail); font-size:12px; border:1px dashed var(--fail); border-radius:4px; }}
  .ptext {{ color:var(--fg); }}
  svg.seg .bg {{ fill:var(--seg-bg); }}
  svg.seg .on {{ fill:var(--seg-on); }}
  svg.seg .off {{ fill:var(--seg-off); }}
  @media (max-width: 520px) {{
    .tuner {{ white-space:normal; }}
    .tuner .tval {{ font-size:15px; }}
    .ftitle {{ font-size:16px; }}
  }}
  .lightbox {{ position:fixed; inset:0; z-index:20; background:rgba(0,0,0,.88); display:flex; align-items:center;
    justify-content:center; padding:2vh 2vw; cursor:zoom-out; }}
  .lightbox[hidden] {{ display:none; }}
  .lightbox img {{ max-width:100%; max-height:100%; background:#000; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>{title}</h1>
    <div class="sub">{generated}<span class="ago" data-ts="{generated_ms}"></span> · total {total_time} · {commit_html}{run_html}</div>
  </header>
  <p class="note">{note}</p>
  <div class="summary">
    <div class="stat"><div class="n">{total}</div><div class="l">Tests</div></div>
    <div class="stat pass"><div class="n">{passed}</div><div class="l">Passed</div></div>
    <div class="stat fail"><div class="n">{failed}</div><div class="l">Failed</div></div>
    <div class="stat"><div class="n">{runtime}</div><div class="l">Runtime</div></div>
    <div class="stat"><div class="n">{images}</div><div class="l">Images</div></div>
    <div class="stat" title="{dumps_list}"><div class="n">{dumps}</div><div class="l">Dumps</div></div>
  </div>
  {sections}
</div>
<div class="lightbox" hidden><img alt=""></div>
{script}
</body>
</html>
"""


# Page behaviour: the live "generated N ago" counter, tag filtering of the
# other tests (same group OR-ed, groups AND-ed), the descriptions' "more"
# switches, a screen at full size on a click and the Copy buttons.  A plain
# string, so its braces need no escaping for .format().
_SCRIPT = """<script>
(function () {
  function fmtAgo(ms) {
    var s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
    var d = Math.floor(s / 86400); s -= d * 86400;
    var h = Math.floor(s / 3600);  s -= h * 3600;
    var m = Math.floor(s / 60);
    var unit = function (n, w) { return n + ' ' + w + (n === 1 ? '' : 's'); };
    var parts = [];
    if (d) parts.push(unit(d, 'day'));
    if (d || h) parts.push(unit(h, 'hour'));
    parts.push(unit(m, 'minute'));
    return '(' + parts.join(', ') + ' ago)';
  }
  function tick() {
    var els = document.querySelectorAll('.ago[data-ts]');
    for (var i = 0; i < els.length; i++) {
      var t = parseInt(els[i].getAttribute('data-ts'), 10);
      els[i].textContent = t ? ' ' + fmtAgo(t) : '';
    }
  }
  tick();
  setInterval(tick, 30000);
})();

(function () {
  var bar = document.querySelector('.others .filters');
  if (!bar) return;
  var chips = Array.prototype.slice.call(bar.querySelectorAll('.fchip'));
  var cards = Array.prototype.slice.call(document.querySelectorAll('.others .card'));
  var status = bar.querySelector('.fstatus');
  var clear = bar.querySelector('.fclear');
  var sel = {};
  cards.forEach(function (c) {
    c._tags = {};
    (c.getAttribute('data-tags') || '').split('|').forEach(function (t) {
      if (!t) return;
      var i = t.indexOf(':');
      var g = t.slice(0, i), n = t.slice(i + 1);
      (c._tags[g] = c._tags[g] || []).push(n);
    });
  });
  function matches(card, selection) {
    for (var g in selection) {
      if (!selection[g] || !selection[g].size) continue;
      var have = card._tags[g] || [];
      var hit = false;
      selection[g].forEach(function (n) { if (have.indexOf(n) >= 0) hit = true; });
      if (!hit) return false;
    }
    return true;
  }
  function apply() {
    var shown = 0;
    cards.forEach(function (c) { var ok = matches(c, sel); c.hidden = !ok; if (ok) shown++; });
    chips.forEach(function (ch) {
      var g = ch.getAttribute('data-group'), n = ch.getAttribute('data-tag');
      var probe = {};
      for (var k in sel) if (k !== g) probe[k] = sel[k];
      var c = cards.filter(function (card) {
        return matches(card, probe) && (card._tags[g] || []).indexOf(n) >= 0;
      }).length;
      ch.querySelector('.fcount').textContent = c;
      ch.classList.toggle('zero', c === 0);
    });
    var any = Object.keys(sel).some(function (g) { return sel[g] && sel[g].size; });
    clear.hidden = !any;
    status.hidden = !any;
    if (any) status.textContent = 'Showing ' + shown + ' of ' + cards.length + ' tests.';
  }
  chips.forEach(function (ch) {
    ch.addEventListener('click', function () {
      var g = ch.getAttribute('data-group'), n = ch.getAttribute('data-tag');
      sel[g] = sel[g] || new Set();
      if (sel[g].has(n)) { sel[g].delete(n); ch.classList.remove('on'); }
      else { sel[g].add(n); ch.classList.add('on'); }
      apply();
    });
  });
  clear.addEventListener('click', function () {
    sel = {};
    chips.forEach(function (c) { c.classList.remove('on'); });
    apply();
  });
  apply();
})();

document.querySelectorAll('.more-btn').forEach(function (btn) {
  btn.addEventListener('click', function () {
    var cut = btn.previousElementSibling.classList.toggle('clamp');
    btn.textContent = cut ? 'more' : 'less';
  });
});

(function () {
  var box = document.querySelector('.lightbox');
  var big = box.querySelector('img');
  document.addEventListener('click', function (e) {
    var t = e.target;
    if (t.tagName === 'IMG' && t.closest('.shot')) {
      big.src = t.src;
      big.alt = t.alt;
      box.hidden = false;
    } else if (!box.hidden && box.contains(t)) {
      box.hidden = true;
    }
  });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') box.hidden = true; });
})();

document.querySelectorAll('.copy-btn').forEach(function (btn) {
  btn.addEventListener('click', function () {
    var body = btn.closest('.body');
    var pre = body.querySelector('pre.log');
    if (!pre) return;
    var text = pre.innerText;
    var done = function () {
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      setTimeout(function () { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1200);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else { fallbackCopy(text); done(); }
  });
});
function fallbackCopy(text) {
  var ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.focus(); ta.select();
  try { document.execCommand('copy'); } catch (e) {}
  document.body.removeChild(ta);
}
</script>"""
