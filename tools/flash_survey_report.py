"""The reports of tools/bootloader_flash_survey.py: Markdown (docs/) and one
self-contained HTML page (a filterable table), from the per-image results."""
from __future__ import annotations

import collections
import datetime as _dt
import html
import json
from pathlib import Path

VERDICTS = [
    ("works", "Works", "backup, burn, readback, reboot and a cold boot of the test application"),
    ("works, packet protocol", "Works, packet protocol", "the same procedure in ALi's packet protocol (tools/ali_packet.py), the only one these loaders speak"),
    ("write path works", "Write path works", "main code format not packable: the renamed original chunk burned, verified, booted"),
    ("partial", "Partial", "the protocol works but a later step failed (see the reason)"),
    ("packet protocol only", "Packet protocol only", "the loader answers comtest with 0xFF - byte: only ALi's packet (format 3) protocol, which the established client does not speak"),
    ("other protocol", "Other protocol", "the loader ignores the paced 'c' and answers another request instead ('upgreq' -> 0x80, the AB CryptoBox and Opticum loaders of one vendor): not the classic shell"),
    ("no handshake", "No handshake", "captured, but no classic comtest echo"),
    ("no capture", "No capture", "paced 'c' from power-on never reached a shell that echoes"),
    ("dump differs", "Dump differs", "the loader's dump differs from the flash"),
    ("no main code chunk", "No main code chunk", "no chunk with ID 0x01FExxxx"),
    ("emulator error", "Emulator error", "the emulator stopped (an unmodelled device or memory window)"),
    ("error", "Tool error", "an exception in the survey tool"),
    ("n/a", "Not applicable", "the emulator does not boot the image, or it is not a flash image"),
]
VERDICT_ORDER = {v: i for i, (v, _l, _d) in enumerate(VERDICTS)}
LABEL = {v: label for v, label, _d in VERDICTS}
STEP_NAMES = ("capture", "handshake", "backup dump", "package", "transfer + burn", "readback dump",
              "reboot + application", "cold boot from written flash")


def _family(r):
    fam = r.get("emulated_family") or (r.get("family") or "?").split(" ")[0]
    return fam


def _step(r, name):
    """The image's last step of that name (a second handshake follows a window capture)."""
    for s in reversed(r.get("steps", ())):
        if s.get("step") == name:
            return s
    return None


def _protocol(r):
    up = _step(r, "upgreq request")
    if up and up.get("answered"):
        return "upgreq"
    hs = _step(r, "handshake")
    return hs.get("protocol", "-") if hs else "-"


def _mark(s):
    if s is None:
        return "-"
    if s.get("skipped") and s.get("ok"):
        return "shared"                 # the bootloader group's representative did the UART dump
    return "ok" if s.get("ok") else "FAIL"


def _cap_time(r):
    for name, suffix in (("window capture", " (window)"), ("capture", "")):
        s = _step(r, name)
        if s and s.get("captured"):
            return f"{s.get('vtime', 0):.1f} s{suffix}"
    return "-"


def _fmt(r):
    s = _step(r, "package")
    if s:
        return s.get("format", "-")
    f = (r.get("facts") or {}).get("format") or {}
    return f.get("kind", "-")


def dump_coverage(results):
    """(images whose UART dumps were run, bootloader groups) among the images that got that far."""
    ran = [r for r in results if (r.get("uart_dumps", True) and _step(r, "backup dump")
                                  and not _step(r, "backup dump").get("skipped"))]
    groups = {r.get("loader_key") for r in results if r.get("loader_key")}
    return len(ran), len(groups)


def summary(results):
    by_verdict = collections.Counter(r.get("verdict") for r in results)
    by_family = collections.defaultdict(collections.Counter)
    for r in results:
        by_family[_family(r)][r.get("verdict")] += 1
    return by_verdict, by_family


def _md_escape(text):
    return str(text).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def write_markdown(results, path: Path, meta: dict):
    by_verdict, by_family = summary(results)
    verdicts_present = [v for v, _l, _d in VERDICTS if by_verdict.get(v)]
    lines = []
    lines.append("# The UART bootloader flash procedure on every image")
    lines.append("")
    lines.append(meta["intro"])
    lines.append("")
    lines.append(f"Generated {meta['date']} by `tools/bootloader_flash_survey.py` on the C++ emulator core; "
                 f"{len(results)} images.")
    lines.append("")
    if meta.get("summary"):
        lines.append("## Summary")
        lines.append("")
        for para in meta["summary"]:
            lines.append(para)
            lines.append("")
    lines.append("## Result per image")
    lines.append("")
    lines.append("| Result | Images | Meaning |")
    lines.append("|---|---:|---|")
    for v, label, desc in VERDICTS:
        if by_verdict.get(v):
            lines.append(f"| {label} | {by_verdict[v]} | {desc} |")
    lines.append("")
    lines.append("## By chip family")
    lines.append("")
    lines.append("| Family | " + " | ".join(LABEL[v] for v in verdicts_present) + " | Total |")
    lines.append("|---|" + "---:|" * (len(verdicts_present) + 1))
    for fam in sorted(by_family, key=lambda f: (-sum(by_family[f].values()), f)):
        c = by_family[fam]
        lines.append(f"| {fam} | " + " | ".join(str(c.get(v, 0) or "") for v in verdicts_present) +
                     f" | {sum(c.values())} |")
    lines.append("")
    for title, body in meta.get("sections", ()):
        lines.append(f"## {title}")
        lines.append("")
        prev_bullet = False
        for para in body:                       # paragraphs, and "- " lines as one list
            bullet = para.startswith("- ")
            if prev_bullet and not bullet:
                lines.append("")
            lines.append(para)
            if not bullet:
                lines.append("")
            prev_bullet = bullet
        if prev_bullet:
            lines.append("")
    dumps = [r for r in results if r.get("kind") == "dump"]
    if dumps:
        lines.append("## The flash dumps read from boxes")
        lines.append("")
        lines.extend(_md_table(dumps))
        lines.append("")
    lines.append("## Every image")
    lines.append("")
    lines.append("Capture = emulated seconds from power-on until the shell echoed the paced 'c'.  "
                 "Format = how the image's main code chunk is packed (lzma: LZMA-alone, the SDK's un7zip; "
                 "lzo: LZO1X behind a 16-byte header).  The step columns are the procedure in order; "
                 "\"shared\" under Backup / Readback: the image's bootloader is byte for byte the one of its "
                 "group's representative (named in the details), whose two UART dumps were checked -- this "
                 "image's written flash was compared with the expected image directly.")
    lines.append("")
    lines.extend(_md_table(results))
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\r\n")   # (CRLF, as the prose docs)


def _md_table(results):
    rows = ["| Image | Box | Family | Result | Capture | Protocol | Backup | Format | Burn | Readback | Reboot | Cold boot | Reason |",
            "|---|---|---|---|---:|---|---|---|---|---|---|---|---|"]
    for r in sorted(results, key=lambda r: (VERDICT_ORDER.get(r.get("verdict"), 99), r.get("image", "").lower())):
        proto = _protocol(r)
        rows.append("| " + " | ".join(_md_escape(x) for x in (
            f"`{r.get('image')}`", r.get("box") or "", _family(r), LABEL.get(r.get("verdict"), r.get("verdict")),
            _cap_time(r), proto, _mark(_step(r, "backup dump")), _fmt(r),
            _mark(_step(r, "transfer + burn")), _mark(_step(r, "readback dump")),
            _mark(_step(r, "reboot + application")), _mark(_step(r, "cold boot from written flash")),
            (r.get("reason") or "")[:160])) + " |")
    return rows


def write_html(results, path: Path, meta: dict):
    by_verdict, by_family = summary(results)
    css = """
:root{--bg:#fbfaf7;--fg:#1d1d1b;--muted:#6b6b66;--line:#e2dfd6;--card:#ffffff;--ok:#1f7a3f;--bad:#b3261e;--warn:#9a6700;--na:#7a7a7a;--accent:#2f5d9e}
@media (prefers-color-scheme: dark){:root:not([data-theme=light]){--bg:#17181a;--fg:#ecebe7;--muted:#a3a29c;--line:#34353a;--card:#202125;--ok:#5cc282;--bad:#f2766d;--warn:#e0b04a;--na:#9a9a9a;--accent:#8fb4ec}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1400px;margin:0 auto;padding:24px 16px 64px}h1{font-size:22px;margin:0 0 6px}h2{font-size:17px;margin:28px 0 10px}
p{max-width:900px}.muted{color:var(--muted)}.chips{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
.chip{border:1px solid var(--line);background:var(--card);border-radius:999px;padding:4px 12px;cursor:pointer;font:inherit;color:inherit}
.chip[aria-pressed=true]{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent)}
input[type=search]{font:inherit;padding:6px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:inherit;width:min(420px,100%)}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
table{border-collapse:collapse;width:100%}th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{position:sticky;top:0;background:var(--card);font-weight:600}td.num{text-align:right;font-variant-numeric:tabular-nums}
.v-works,.v-write{color:var(--ok);font-weight:600}.v-partial{color:var(--warn);font-weight:600}.v-bad{color:var(--bad);font-weight:600}.v-na{color:var(--na)}
.s-ok{color:var(--ok)}.s-FAIL{color:var(--bad);font-weight:600}code{font-size:12px}
details summary{cursor:pointer}pre{white-space:pre-wrap;font-size:12px;max-height:260px;overflow:auto;background:var(--bg);padding:8px;border-radius:6px}
"""
    def vclass(v):
        return {"works": "v-works", "works, packet protocol": "v-works", "write path works": "v-write",
                "partial": "v-partial", "n/a": "v-na"}.get(v, "v-bad")
    rows = []
    for r in sorted(results, key=lambda r: (VERDICT_ORDER.get(r.get("verdict"), 99), r.get("image", "").lower())):
        steps = "".join(f'<td class="s-{_mark(_step(r, n))}">{_mark(_step(r, n))}</td>' for n in STEP_NAMES[2:])
        detail = html.escape(json.dumps({k: v for k, v in r.items() if k not in ("facts",)}, indent=1)[:6000])
        rows.append(
            f'<tr data-v="{html.escape(r.get("verdict") or "")}" data-k="{html.escape(r.get("kind") or "")}">'
            f'<td><code>{html.escape(r.get("image", ""))}</code><br><span class="muted">{html.escape(r.get("box") or "")}</span></td>'
            f'<td>{html.escape(_family(r))}</td>'
            f'<td class="{vclass(r.get("verdict"))}">{html.escape(LABEL.get(r.get("verdict"), str(r.get("verdict"))))}</td>'
            f'<td class="num">{_cap_time(r)}</td><td>{html.escape(_protocol(r))}</td>'
            f'{steps}<td>{html.escape(_fmt(r))}</td>'
            f'<td><details><summary>{html.escape((r.get("reason") or "")[:140])}</summary><pre>{detail}</pre></details></td></tr>')
    chips = ['<button class="chip" data-f="" aria-pressed="true">All ' + str(len(results)) + '</button>']
    for v, label, _d in VERDICTS:
        if by_verdict.get(v):
            chips.append(f'<button class="chip" data-f="{html.escape(v)}" aria-pressed="false">{html.escape(label)} {by_verdict[v]}</button>')
    fam_rows = []
    present = [v for v, _l, _d in VERDICTS if by_verdict.get(v)]
    for fam in sorted(by_family, key=lambda f: (-sum(by_family[f].values()), f)):
        c = by_family[fam]
        fam_rows.append("<tr><td>" + html.escape(fam) + "</td>" +
                        "".join(f'<td class="num">{c.get(v, 0) or ""}</td>' for v in present) +
                        f'<td class="num">{sum(c.values())}</td></tr>')
    def prose(body):
        """Paragraphs and "- " list lines, with `code` spans."""
        out, items = [], []
        def inline(text):
            parts = html.escape(text).split("`")
            return "".join(f"<code>{p}</code>" if i % 2 else p for i, p in enumerate(parts))
        for line in list(body) + [""]:
            if line.startswith("- "):
                items.append(f"<li>{inline(line[2:])}</li>")
                continue
            if items:
                out.append("<ul>" + "".join(items) + "</ul>")
                items = []
            if line.strip():
                out.append(f"<p>{inline(line)}</p>")
        return "".join(out)
    summary_html = (f"<h2>Summary</h2>{prose(meta['summary'])}" if meta.get("summary") else "")
    sections = "".join(f"<h2>{html.escape(t)}</h2>{prose(body)}" for t, body in meta.get("sections", ()))
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bootloader flash survey</title><style>{css}</style></head><body><main>
<h1>The UART bootloader flash procedure on every image</h1>
<p>{html.escape(meta["intro"])}</p>
<p class="muted">Generated {html.escape(meta["date"])} by tools/bootloader_flash_survey.py on the C++ emulator core; {len(results)} images.</p>
{summary_html}
<h2>By chip family</h2><div class="wrap"><table><thead><tr><th>Family</th>{"".join(f"<th>{html.escape(LABEL[v])}</th>" for v in present)}<th>Total</th></tr></thead><tbody>{"".join(fam_rows)}</tbody></table></div>
{sections}
<h2>Every image</h2>
<div class="chips">{"".join(chips)}</div>
<p><input type="search" id="q" placeholder="Filter by image, box or family"> <label><input type="checkbox" id="dumps"> only flash dumps read from boxes</label></p>
<div class="wrap"><table id="t"><thead><tr><th>Image</th><th>Family</th><th>Result</th><th>Capture</th><th>Protocol</th>
<th>Backup</th><th>Package</th><th>Burn</th><th>Readback</th><th>Reboot</th><th>Cold boot</th><th>Format</th><th>Reason / details</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>
<script>
const chips=[...document.querySelectorAll('.chip')];let f='';
function apply(){{const q=document.getElementById('q').value.toLowerCase();const d=document.getElementById('dumps').checked;
for(const tr of document.querySelectorAll('#t tbody tr')){{const ok=(!f||tr.dataset.v===f)&&(!q||tr.textContent.toLowerCase().includes(q))&&(!d||tr.dataset.k==='dump');tr.style.display=ok?'':'none';}}}}
chips.forEach(c=>c.addEventListener('click',()=>{{f=c.dataset.f;chips.forEach(x=>x.setAttribute('aria-pressed',x===c));apply();}}));
document.getElementById('q').addEventListener('input',apply);document.getElementById('dumps').addEventListener('change',apply);
</script></main></body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(page, encoding="utf-8")


def _families(rs):
    c = collections.Counter(_family(r) for r in rs)
    return ", ".join(f"{f} {n}" for f, n in sorted(c.items(), key=lambda x: (-x[1], x[0])))


def _boxes(rs, limit=8):
    """The images' dumps/ folders (one per box model)."""
    names = sorted({r.get("image", "").split("/")[0] if "/" in r.get("image", "") else (r.get("box") or r.get("image", ""))
                    for r in rs})
    more = len(names) - limit
    return ", ".join(names[:limit]) + (f" and {more} more" if more > 0 else "")


def _n(k, word="image"):
    return f"{k} {word}" + ("" if k == 1 else "s")


def narrative(results):
    """(summary paragraphs, [(title, lines)]): the report's explanations, with
    every number taken from the results."""
    by = collections.defaultdict(list)
    for r in results:
        by[r.get("verdict")].append(r)
    n = len(results)
    na = by["n/a"]
    tried = n - len(na)
    classic = by["works"] + by["write path works"]
    packet_works = by["works, packet protocol"]
    works = classic + packet_works
    fmt = collections.Counter(_fmt(r) for r in by["works"] + packet_works)
    wdt = [r for r in works if (_step(r, "reboot + application") or {}).get("watchdog_reset")]
    big = [r for r in works if ((r.get("facts") or {}).get("flash_size") or 0) > 4 << 20]
    window = [r for r in results if r.get("capture_mode") == "window"]
    dumped, groups = dump_coverage(results)

    def pct(k):
        return f"{100.0 * k / tried:.0f} %" if tried else "-"
    rest = [(len(by["packet protocol only"]), "packet protocol, not flashed"),
            (len(by["other protocol"]), "another request word"),
            (len(by["no capture"]), "not captured by the paced 'c'"),
            (len(by["no handshake"]), "captured without a classic handshake"),
            (len(by["partial"]), "stopped part-way"),
            (len(by["emulator error"]) + len(by["error"]), "an emulator or tool error")]
    summary = [
        f"Of the {_n(n)}, {tried} have a bootloader the emulator boots, and {len(by['works'])} of those "
        f"({pct(len(by['works']))}) take the established procedure end to end: capture, handshake, a CRC-checked "
        f"backup, the burn of a new main code chunk, a byte-for-byte readback, the loader's reboot into the new "
        f"application and a cold boot from the written flash."
        + (f" {len(by['write path works'])} more go through it with their own main code burned again, renamed "
           f"(its format -- encrypted or unknown -- cannot carry the test application)."
           if by["write path works"] else ""),
    ]
    if packet_works:
        summary.append(
            f"{len(packet_works)} more ({pct(len(packet_works))}) take the same procedure in ALi's packet "
            f"protocol, the only one their loaders speak (tools/ali_packet.py, written from the SDK's own loader "
            f"sources): {len(works)} of {tried} ({pct(len(works))}) in all.")
    if any(k for k, _label in rest):
        summary.append("The rest: " + "; ".join(f"{label} {k}" for k, label in rest if k) +
                       ". The sections below explain each group.")
    method = [
        "- UART: the host's bytes enter the 16-byte receive FIFO at 115200 baud line rate. Protocol bytes wait "
        "for room (as with flow control: the emulated CPU is slower than the real chip, so a loader can fall "
        "behind); the paced capture 'c' are lost when they meet a full FIFO, as on the wire. The C++ core logs the "
        "loader's transmitted bytes itself (a transmit-register rule), so a dump costs what the loader's own code "
        "costs: emulated seconds are instructions / 50 M.",
        f"- One pair of UART dumps per bootloader: the {_n(n)} hold {groups} distinct bootloaders (the bootloader "
        f"chunk's bytes and the flash size). The backup and readback dumps run on one image of each and on every "
        f"flash dump read from a box ({_n(dumped)} in all); the other images of a group still go through capture, "
        f"handshake, transfer, burn, reboot and cold boot, and their written flash is compared with the expected "
        f"image directly.",
        f"- The test application (firmware/maciej_app/hello.c: a banner, and 'p' answered with 'pong survey') is "
        f"built for each image's main-code load address and UART and packed in the image's own main-code format: "
        f"LZMA-alone, as the SDK's un7zip reads it ({fmt.get('lzma', 0)} working images), or LZO1X behind a "
        f"16-byte header of sizes and Adler-32 sums ({fmt.get('lzo', 0)}; the M3801 loaders built by vic.wang). "
        f"It replaces the main code chunk, CRC and all; the rest of the flash must stay as it was. Its start-up "
        f"code (survey_start.S) copies it to the address it was linked for when a loader starts the main code "
        f"elsewhere: with the chunk's load address left 0xFFFFFFFF most loaders use 0x80000200, but some use "
        f"their own default (the Amiko / Amstar M3602 builds unpack and start it at 0x80008000).",
        "- CRC checks: the C3505 chip model (and the C3503, built on it) normally rewrites the main code "
        "chunk's CRC to 'NCRC' (no CRC) so its loaders skip that check; the survey turns that off, so those "
        "loaders check the CRC of the chunk the survey writes ('CRC Check Result : Pass') as on the box. Every "
        "written chunk's CRC is also recomputed by the survey itself.",
        f"- Watchdog reboots: the loaders of {_n(len(wdt), 'working image')} ({_families(wdt) or 'none'}) answer "
        f"'reboot' by arming the watchdog for an immediate reset (0xB8018500 = 0xFFFFF000, then 0x67) and "
        f"spinning. The emulator has no watchdog reset, so the survey starts a fresh machine from the flash the "
        f"loader wrote -- what the chip's reset does.",
        f"- Flash above 0xB0000000: newer M3503 / C3505 loaders read an 8 or 16 MB flash linearly from 0xAFC00000 "
        f"on, past 0xB0000000, where the SDK's older loaders switch windows; the emulator now maps the flash's "
        f"tail there too ({_n(len(big), 'working image')} with more than 4 MB of flash).",
    ]
    sections = [("How the emulator runs the procedure", method)]
    packet_all = packet_works + by["packet protocol only"]
    if packet_all:
        sections.append(("The packet protocol", [
            f"- {_n(len(packet_all))} ({_families(packet_all)}) have loaders built with the SDK's "
            f"TRANSFER_FORMAT3_ONLY: they capture and echo 'comtest 2' like the others, then answer the two "
            f"handshake bytes with 0xFF minus each byte (0xA7 0xA7 for 'XX'). They speak only ALi's packet "
            f"(format 3) upgrade protocol, the one ALi's PC upgrade tools use, and tools/maciej_uart.py does not.",
            "- tools/ali_packet.py speaks it, written from the SDK's own loader sources "
            "(refs/BootLoader/SRC/lib/libapplet/libbootupg3: Packet.c, lib_ash.c, lib_ashcmd.c). Every command, "
            "data block and status travels in a packet -- 'HEAD', type, index, length, a header CRC, the data and "
            "its CRC (CRC-32/MPEG-2, big-endian numbers); the dump comes as 1024-byte packets the host asks for one "
            "by one, and burn reports every sector it writes. After the same capture, '@' as the first handshake "
            "byte selects it (on these loaders any byte does). The commands are the classic ones: address, "
            "transfer, burn, dump, reboot.",
            f"- With it the survey runs the same procedure on them: {len(packet_works)} work end to end"
            + (f" ({_boxes(packet_works)})" if packet_works else "") + ".",
        ]))
    odd = []
    for r in sorted(by["packet protocol only"], key=lambda r: r.get("image", "")):
        odd.append(f"- Packet protocol, not flashed: `{r.get('image')}` ({_family(r)}): {r.get('reason', '')[:300]}")
    if window:
        times = [_step(r, "window capture").get("vtime", 0) for r in window]
        span = f"{min(times):.0f}" if max(times) - min(times) < 1 else f"{min(times):.0f} to {max(times):.0f}"
        odd.append(
            f"- Window capture ({_n(len(window))}: {_boxes(window)}): these M3602 loaders look at the UART only "
            f"for about 0.35 s, after their main-code check ({span} emulated seconds after power-on), echo "
            f"what arrived meanwhile and boot on unless 'comtest' arrives in that moment. The established "
            f"capture's carriage return and pause end the window, so the survey holds them on a fresh machine by "
            f"sending 'comtest 2' straight after the first echo (they then speak only the packet protocol). On a "
            f"real box the check probably comes after a few seconds of decompression instead of a minute.")
    noisy = [r for r in results if any(s.get("noise") for s in r.get("steps", ()))]
    if noisy:
        lines = sorted({line for r in noisy for s in r.get("steps", ()) for line in s.get("noise", ())})
        odd.append(
            f"- Debug lines ({_n(len(noisy))}: {_boxes(noisy)}): the loader's drivers print "
            + ", ".join(f"'{line}'" for line in lines) +
            " between the protocol's bytes -- after the comtest echo, and once per 1 KB of a dump -- so the "
            "shipped client stops at the handshake. The survey drops those lines from what it reads, and lets "
            "the loader go quiet after the handshake (bytes sent while it updates its panel are lost); then the "
            "procedure goes through.")
    if by["other protocol"]:
        odd.append(
            f"- Other protocol ({_n(len(by['other protocol']))}: {_boxes(by['other protocol'])}): the loader "
            f"ignores 'c' and boots, but answers the word 'upgreq' with one byte, 0x80, and then reads whatever "
            f"comes without answering -- neither the classic 'comtest' nor ALi's packets: an upgrade protocol of its "
            f"own (the vendor's PC tool's), not worked out here.")
    for verdict, title in (("no capture", "No capture"), ("no handshake", "No handshake"),
                           ("partial", "Partial"), ("emulator error", "Emulator error"), ("error", "Tool error")):
        for r in sorted(by[verdict], key=lambda r: r.get("image", "")):
            text = f"- {title}: `{r.get('image')}` ({_family(r)}): {r.get('reason', '')[:300]}"
            cap = _step(r, "capture") or {}
            bad = [c.get("name") for c in (r.get("facts") or {}).get("chunks", ()) if c.get("crc_ok") is False]
            if verdict == "no capture" and bad:
                text += (f" -- the image's own {', '.join(bad)} chunk fails its CRC (the file's checksum does not "
                         f"match its data: a modified build or a damaged read), so the loader's check fails"
                         + (" ('CRC Check Result : Fail')" if "CRC Check Result : Fail" in cap.get("boot_output", "")
                            else "") + " and it opens no shell")
            elif verdict == "no capture" and "nothing read the UART" in r.get("reason", ""):
                if _family(r) == "M3329":
                    text += (" -- its loader prints on the UART but never reads it on the way to the main code "
                             "(traced on the Bigsat DSR 6500 Lux, both UARTs): it has no 'c' window; the SDK's "
                             "loaders open their shell otherwise only when the main code fails its check")
                elif not cap.get("boot_output"):
                    text += " -- and printed nothing on it: this loader does not use the UART the survey drives"
            odd.append(text)
    if by["no capture"]:
        odd.append(
            "- Double check of the no-capture images: on ILTV HD, Openbox X3, Skybox F4, the Amiko Mini Combo "
            "Extra Edision build and the Ferguson Ariva 160 Combo, tools/maciej_uart.py's own timed capture ('c' "
            "for 5 or 60 s whatever comes back, then the handshake) and the whole word 'comtest 2' sent from "
            "power-on reach no shell either: the survey's echo-based capture is not what stops them.")
    if na:
        reasons = collections.Counter(r.get("reason", "") for r in na)
        odd.append(f"- Not applicable ({_n(len(na))}): " +
                   "; ".join(f"{k} ({v})" for k, v in reasons.most_common()))
    if odd:
        sections.append(("Images the established procedure does not flash", odd))
    sections.append(("What a pass means", [
        "A 'works' row means the image's own bootloader code, run instruction by instruction, accepted the "
        "established client's bytes, wrote exactly the flash the client expected (nothing outside the main code "
        "chunk changed), and booted the application it was given. The same procedure ran on a real Opticum STB "
        "HD N2 (dump_maciej.bin) with the results it has here (docs/maciej_bootloader.md). On another real box "
        "the timing differs -- its CPU runs several times faster than the emulator's 50 M instructions per "
        "second, so its loader drains the FIFO sooner and reaches its capture check earlier -- and parts the "
        "emulator does not model (a flash chip's protection bits, the board's UART wiring, a loader that also "
        "looks at a front-panel key) can still stop it. Read a 'works' row as: this bootloader implements the "
        "classic protocol and its flash-writing path the way the client expects.",
    ]))
    return summary, sections


INTRO = ("Each image boots in the emulator and goes through tools/maciej_uart.py's flash procedure, the one "
         "verified on a physical Opticum STB HD N2: 'c' sent every 50 ms from power-on to hold the bootloader, "
         "the 'comtest 2' handshake, a CRC-checked full 'dump' as the backup, 'address' + 'transfer' + 'burn' "
         "of a main code chunk carrying a small test application (the demo's banner and a 'p' -> pong reply), "
         "a second full 'dump' compared byte for byte, 'reboot', the application's banner and pong, and a cold "
         "boot of a fresh machine from the flash the bootloader wrote.  Only UART bytes go in, at 115200 baud "
         "through a 16-byte receive FIFO.")


def write_reports(results, md_path: Path, html_path: Path, sections=None):
    summary, auto = narrative(results)
    meta = {"intro": INTRO, "date": _dt.date.today().isoformat(), "summary": summary,
            "sections": list(auto if sections is None else sections)}
    write_markdown(results, md_path, meta)
    write_html(results, html_path, meta)
