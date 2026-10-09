"""Render the self-test results as one self-contained HTML page (report/index.html).

run_all_tests.py collects, for every test script it ran: pass / fail, wall
time, the script's docstring, the [PASS] / [FAIL] lines it printed (its
assertions), its whole output, and the images it attached through
report_artifacts.py -- screen captures as PNG files and front-panel LED
displays as segment bytes.  This module turns that into a single HTML file
(inline CSS / JS, the PNGs embedded as data URIs, the LED displays drawn as
inline SVG), so it reads the same opened from disk, as a CI artifact and
published to GitHub Pages.

Modelled on the BekenSimulator report (tests/report.py there): summary cards,
tag filters, one expandable card per test with tabs.
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


def _images_html(r):
    """The Images tab: screen captures (embedded) and LED displays (SVG)."""
    items = []
    for img in r.get("images", []):
        cap = html.escape(img.get("caption") or os.path.basename(img["path"]))
        if img.get("missing"):
            items.append('<figure class="shot missing"><div class="nofile">file not found</div>'
                         '<figcaption>%s<br><code>%s</code></figcaption></figure>'
                         % (cap, html.escape(os.path.basename(img["path"]))))
            continue
        try:
            src = _data_uri(img["path"])
        except OSError:
            items.append('<figure class="shot missing"><div class="nofile">unreadable</div>'
                         '<figcaption>%s</figcaption></figure>' % cap)
            continue
        items.append('<figure class="shot"><a href="%s" target="_blank"><img src="%s" alt="%s" loading="lazy"></a>'
                     '<figcaption>%s</figcaption></figure>' % (src, src, cap, cap))
    for p in r.get("panels", []):
        text = html.escape(p.get("text") or "")
        cap = html.escape(p.get("caption") or "front panel")
        items.append('<figure class="shot panel">%s<figcaption>%s%s</figcaption></figure>'
                     % (panel_svg(p["digits"], 1.4), cap,
                        (' <code class="ptext">[%s]</code>' % text) if text else ""))
    if not items:
        return '<p class="empty">This test attached no images (see report_artifacts.py).</p>'
    return '<div class="gallery">%s</div>' % "".join(items)


def _tag_class(tag):
    return "tag " + {"dump": "dump", "kind": "kind", "data": "data"}.get(tag.get("group", "feature"), "feat")


def _tags_html(r):
    return "".join('<span class="%s">%s</span>' % (_tag_class(t), html.escape(t["name"]))
                   for t in r.get("tags", []))


def _test_card(r):
    ok = r["passed"]
    status_cls = "pass" if ok else "fail"
    status_txt = "PASS" if ok else ("CRASH" if r.get("crashed") else "FAIL")
    checks = r.get("checks") or []
    checks_html = "".join(
        '<li class="%s"><span class="chk">%s</span>%s</li>'
        % ("found" if c["ok"] else "missing", "✓" if c["ok"] else "✗", html.escape(c["text"]))
        for c in checks)
    if not checks:
        checks_html = '<li class="none">no [PASS] / [FAIL] lines; the verdict is the exit code (%d)</li>' % r.get("exit_code", 0)
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
    timed = ' <span class="warn">(timed out)</span>' if r.get("timed_out") else ""
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
        <p class="desc">{desc}</p>
        <div class="meta"><span class="args"><code>python {script}</code></span></div>
        <div class="checks"><div class="checks-title">Assertions</div><ul>{checks}</ul></div>
        <div class="tabbar">
          <button class="tab-btn active" type="button" data-tab="log">Output</button>
          <button class="tab-btn{img_dis}" type="button" data-tab="images">Images{img_n}</button>
          <button class="copy-btn" type="button">Copy</button>
        </div>
        <div class="tab-panel" data-panel="log"><pre class="log">{log}</pre></div>
        <div class="tab-panel hidden" data-panel="images">{images}</div>
      </div>
    </details>
    """.format(
        status_cls=status_cls, status_txt=status_txt,
        name=html.escape(r["name"]), secs=_fmt_secs(r["elapsed"]), timed=timed,
        imgs=("%d image%s" % (n_img, "" if n_img == 1 else "s")) if n_img else "",
        tags=_tags_html(r),
        tagdata=html.escape("|".join("%s:%s" % (t.get("group", "feature"), t["name"]) for t in r.get("tags", []))),
        thumb=thumb,
        desc=html.escape(r.get("description") or "(no description)"),
        script=html.escape(r["script"]),
        checks=checks_html,
        img_dis="" if n_img else " disabled", img_n=(" (%d)" % n_img) if n_img else "",
        log=_highlight(r.get("output", ""), checks),
        images=_images_html(r),
    )


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
    page = _PAGE.format(
        title=html.escape(TITLE),
        overall_cls="pass" if failed == 0 else "fail",
        passed=passed, failed=failed, total=len(results),
        runtime=_fmt_compact(meta.get("total_time", 0)),
        images=n_img,
        dumps=len(dumps), dumps_list=html.escape(", ".join(dumps)),
        total_time=_fmt_total(meta.get("total_time", 0)),
        generated=html.escape(meta.get("generated_at", "")), generated_ms=generated_ms,
        commit_html=commit_html, run_html=run_html,
        note=html.escape(meta.get("note", "")),
        filters=_filters_html(results),
        cards="".join(_test_card(r) for r in results),
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
  .wrap {{ max-width:1040px; margin:0 auto; padding:28px 18px 60px; }}
  header h1 {{ margin:0 0 4px; font-size:22px; }}
  .sub {{ color:var(--muted); font-size:13px; margin-bottom:18px; }}
  .sub a {{ color:var(--accent); text-decoration:none; }}
  .ago {{ font-style:italic; opacity:.8; white-space:nowrap; }}
  .note {{ color:var(--muted); font-size:13px; margin:-10px 0 16px; }}
  .summary {{ display:flex; gap:10px; flex-wrap:wrap; margin:0 0 22px; }}
  .stat {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:12px 16px; min-width:96px; }}
  .stat .n {{ font-size:24px; font-weight:700; }}
  .stat .l {{ font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }}
  .stat.pass .n {{ color:var(--pass); }} .stat.fail .n {{ color:var(--fail); }}
  .filters {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:12px 14px; margin:0 0 16px; }}
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
  summary {{ display:flex; align-items:center; gap:10px; padding:12px 16px; cursor:pointer; list-style:none; }}
  summary::-webkit-details-marker {{ display:none; }}
  .dot {{ width:10px; height:10px; border-radius:50%; flex:0 0 auto; background:var(--pass); }}
  .card.fail .dot {{ background:var(--fail); }}
  .head {{ flex:1; display:flex; flex-direction:column; gap:6px; min-width:0; }}
  .row1 {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .title {{ font-weight:600; flex:1; min-width:0; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:14px; }}
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
  .desc {{ color:var(--fg); margin:12px 0; white-space:pre-line; }}
  .meta {{ display:flex; gap:14px; flex-wrap:wrap; align-items:center; margin-bottom:12px; }}
  .args code {{ color:var(--muted); font-size:12px; }}
  .checks-title {{ font-size:12px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); margin:14px 0 6px; }}
  .checks ul {{ list-style:none; margin:0; padding:0; }}
  .checks li {{ display:flex; gap:8px; align-items:baseline; padding:2px 0; font-size:13.5px; }}
  .checks li.none {{ color:var(--muted); font-style:italic; }}
  .checks .chk {{ font-weight:700; width:14px; flex:0 0 auto; }}
  .checks li.found .chk {{ color:var(--pass); }}
  .checks li.missing {{ color:var(--fail); }}
  .checks li.missing .chk {{ color:var(--fail); }}
  .tabbar {{ display:flex; align-items:center; gap:4px; margin:16px 0 0; border-bottom:1px solid var(--line); }}
  .tab-btn {{ font-size:12px; padding:6px 12px; border:1px solid transparent; border-bottom:none; background:none;
    color:var(--muted); cursor:pointer; border-radius:6px 6px 0 0; }}
  .tab-btn:hover:not(.disabled) {{ color:var(--fg); }}
  .tab-btn.active {{ background:var(--bg); border-color:var(--line); color:var(--fg); font-weight:700; margin-bottom:-1px; }}
  .tab-btn.disabled {{ opacity:.45; cursor:default; }}
  .tabbar .copy-btn {{ margin-left:auto; }}
  .tab-panel {{ padding-top:10px; }}
  .tab-panel.hidden {{ display:none; }}
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
  .gallery {{ display:flex; gap:14px; flex-wrap:wrap; align-items:flex-start; }}
  .shot {{ margin:0; background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:8px; max-width:100%; }}
  .shot img {{ display:block; max-width:480px; width:100%; height:auto; border-radius:4px; background:#000; }}
  .shot figcaption {{ font-size:12px; color:var(--muted); margin-top:6px; max-width:480px; }}
  .shot.panel {{ display:flex; flex-direction:column; align-items:center; }}
  .shot.missing .nofile {{ width:200px; height:60px; display:flex; align-items:center; justify-content:center;
    color:var(--fail); font-size:12px; border:1px dashed var(--fail); border-radius:4px; }}
  .ptext {{ color:var(--fg); }}
  svg.seg .bg {{ fill:var(--seg-bg); }}
  svg.seg .on {{ fill:var(--seg-on); }}
  svg.seg .off {{ fill:var(--seg-off); }}
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
  {filters}
  {cards}
</div>
{script}
</body>
</html>
"""


# Page behaviour: the live "generated N ago" counter, tag filtering (same
# group OR-ed, groups AND-ed), tab switching and the Copy buttons.  A plain
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
  var bar = document.querySelector('.filters');
  if (!bar) return;
  var chips = Array.prototype.slice.call(bar.querySelectorAll('.fchip'));
  var cards = Array.prototype.slice.call(document.querySelectorAll('.card'));
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

document.querySelectorAll('.tab-btn').forEach(function (btn) {
  btn.addEventListener('click', function () {
    if (btn.classList.contains('disabled')) return;
    var body = btn.closest('.body');
    body.querySelectorAll('.tab-btn').forEach(function (b) { b.classList.remove('active'); });
    btn.classList.add('active');
    body.querySelectorAll('.tab-panel').forEach(function (p) {
      p.classList.toggle('hidden', p.getAttribute('data-panel') !== btn.getAttribute('data-tab'));
    });
  });
});
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
