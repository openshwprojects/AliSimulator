"""
Interactive "TV": boots any firmware dump in the simulator, shows what its OSD
draws (live, through the GE model and the GMA display layer) and lets you
drive the menus with a virtual IR remote control.

    python tv_gui.py [dump_maciej.bin] [--scale 0.75] [--family Auto|M3801|M3602|M3503|C3505|M3821|M3329] [--json sidecar.json] [--signal]

Top toolbar:
  * Dump selector: pick any of the 100 firmware dumps in dumps/ from the
    dropdown (grouped by folder/model with its chip family), or click
    "Browse..." to open any .bin / .abs file from disk.
  * Family: Auto (detects the chip family from the image's boot vector and
    chunk layout via chips.detect) or force a specific family (M3801, M3602,
    M3503, C3505, M3821, M3329).
  * Sidecar: Auto (uses <dump>.json next to the image when present), None
    (pure autodetect without sidecar overrides), any board preset from the
    catalog, or "JSON..." to browse for a custom .json sidecar file.
  * IR: Auto (from the sidecar or ir_remote.IR_CODINGS) or override live
    (nec, ext00, necfirst, cmd).
  * Signal + TS: feed a locked tuner / demodulator signal and the synthetic
    DVB transport stream multiplexer (ts_mux.Mux) so channel scans find and
    store services.

Keyboard: arrows, Enter = OK, Esc / Backspace = EXIT, M = MENU, I = INFO,
0-9, PgUp / PgDn = CH+ / CH-, +/- = VOL, F1-F4 = red / green / yellow / blue.

F5 (or the button under the remote) swaps the screen for the UART console:
everything the firmware printed, and a line typed there is sent to its UART
(dump_maciej's console task listens for 'startconsole', answers '*** CONSOLE
ACTIVATED ***' and then takes commands: HELP lists DELETE TOUCH READ RCU FLAG
MAINCODE CHANNELS VERSION CLS HEAP SENDMSG HMSG TIME GPIOCONFIG ADDDUMMY EXIT
REBOOT).  Remote keys are not taken while the UART line has the focus.

Under the remote: the front panel's 4-digit LED display (what the firmware
writes to its LED-driver chip over bit-banged GPIO: a TM1650 on I2C or a
TM1628-class 3-wire chip, chosen per dump in front_panel.py) and its key
matrix as buttons; the firmware's panel driver polls the chip's key register
and the decoder answers a pressed button once (dump_maciej
reacts to KI1/DIG4 = up and KI2/DIG4 = down; each press is delivered as one
key event, the firmware repeats a key for every poll it is held).

The keys go through the emulated M6303 IR receiver as NEC frames: the
firmware's own interrupt handler, NEC decoder and key table turn them into
UI key messages (see ir_remote.py and AliMipsSimulator.press_key).  The
remote works once the application is up (dump_maciej: the first screen is
drawn about 3 minutes after the start).

Be patient: the emulated firmware redraws a menu page with a few hundred GE
commands, which takes it several seconds of its own time and 30-50 s of
wall-clock time, so a key shows its effect that much later; keys pressed
meanwhile queue up ("+N queued" in the status line) and are served in
order.  A key the firmware's key table does not have (dump_maciej: VOL, CH,
EPG, MUTE, GREEN, POWER) is reported in the status line and does nothing
(dump_maciej's POWER is its virtual key 19: sim.press_key(19) puts the box
into standby, which the simulator cannot wake).  dump_maciej's wizard starts
a DVB-T channel search when OK is
pressed on its aspect-ratio page: that screen keeps redrawing its progress
for about an hour and ignores every key except EXIT (which takes a minute or
two to act).
"""
import os
import queue
import re
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, ttk

import numpy as np

import chips
import dump_catalog
import ir_remote
from front_panel import SEG_POLYS, make_panel
from simulator import DUMPS_DIR, AliMipsSimulator, flash_size_for, resolve_dump

# Front panel: the dump's LED-driver chip (front_panel.py: a TM1650 on I2C or
# a TM1628-class 3-wire chip, each on its bit-bang GPIO pins) drives a 4-digit
# 7-segment display and scans a key matrix.  The buttons below the display
# press each matrix position; dump_maciej's panel driver reacts to KI1/DIG4
# (up / CH+) and KI2/DIG4 (down / CH-) only (every code was tried on its
# wizard).  A board without the chip shows a blank display and ignores them.
# 7-segment layout: front_panel.SEG_POLYS (bit 0..6 = segments a..g, bit 7 = DP)
SEG_ON, SEG_OFF = "#ff3b30", "#2a1210"

# (label, key name, grid row, column) of the on-screen remote
REMOTE = [
    ("POWER", "POWER", 0, 0), ("MENU", "MENU", 0, 1), ("EXIT", "EXIT", 0, 2),
    ("TV/R", "TVRADIO", 1, 0), ("\u25b2", "UP", 1, 1), ("RECALL", "RECALL", 1, 2),
    ("\u25c0", "LEFT", 2, 0), ("OK", "OK", 2, 1), ("\u25b6", "RIGHT", 2, 2),
    ("PG+", "PAGE+", 3, 0), ("\u25bc", "DOWN", 3, 1), ("PG-", "PAGE-", 3, 2),
    ("1", "1", 4, 0), ("2", "2", 4, 1), ("3", "3", 4, 2),
    ("4", "4", 5, 0), ("5", "5", 5, 1), ("6", "6", 5, 2),
    ("7", "7", 6, 0), ("8", "8", 6, 1), ("9", "9", 6, 2),
    ("INFO", "INFO", 7, 0), ("0", "0", 7, 1), ("EPG", "EPG", 7, 2),
    ("CH+", "CH+", 8, 0), ("VOL+", "VOL+", 8, 1), ("FAV", "FAV", 8, 2),
    ("CH-", "CH-", 9, 0), ("VOL-", "VOL-", 9, 1), ("MUTE", "MUTE", 9, 2),
    ("AUDIO", "AUDIO", 10, 0), ("SUBT", "SUBTITLE", 10, 1), ("TEXT", "TEXT", 10, 2),
]
COLOURS = [("RED", "#c0392b"), ("GREEN", "#27ae60"), ("YELLOW", "#d4ac0d"), ("BLUE", "#2471a3")]
REFRESH_S = 1.5         # screen refresh interval while the GE keeps drawing
CPU_OSD_REFRESH_S = 3.0 # fallback screen refresh interval for CPU-drawn OSDs (sim.ge_ops == 0)
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_CTRL_TRANS = str.maketrans({i: "·" for i in range(32) if i not in (9, 10)})
KEYMAP = {
    "Up": "UP", "Down": "DOWN", "Left": "LEFT", "Right": "RIGHT", "Return": "OK",
    "KP_Enter": "OK", "Escape": "EXIT", "BackSpace": "EXIT", "m": "MENU", "i": "INFO",
    "Prior": "CH+", "Next": "CH-", "plus": "VOL+", "minus": "VOL-", "KP_Add": "VOL+",
    "KP_Subtract": "VOL-", "F1": "RED", "F2": "GREEN", "F3": "YELLOW", "F4": "BLUE",
    "e": "EPG", "p": "POWER", "f": "FAV", "u": "MUTE", "a": "AUDIO", "s": "SUBTITLE",
    "t": "TEXT", "r": "RECALL", "v": "TVRADIO", "space": "PAUSE", "l": "LIST",
}
FAMILIES = list(chips.FAMILY_CHOICES)
IR_CODINGS = ["Auto", "nec", "ext00", "necfirst", "cmd"]
SIDECAR_AUTO = dump_catalog.SIDECAR_AUTO
SIDECAR_NONE = dump_catalog.SIDECAR_NONE


class TvGui:
    def __init__(self, root, dump, scale, family="Auto", json_path=None, signal=False):
        self._catalog = dump_catalog.catalog_entries()
        self._label_to_path = {label: path for label, path, _sc in self._catalog}
        dump = dump_catalog.resolve_catalog_dump(dump, self._catalog)
        self.root, self.dump, self.scale = root, dump, scale
        self.keys = queue.Queue()
        self.frame = None               # newest PPM bytes (or RGB array) from the emulation thread
        self.status = "booting..."
        self._shown_status = None
        self.stop = False
        self._reload_requested = False
        self._current_sim = None
        root.title(f"AliSimulator TV - {os.path.basename(dump)}")
        root.configure(bg="#111")

        # Sidecar presets from catalog
        self._sidecar_presets = dump_catalog.sidecar_presets(self._catalog)

        # ---- Top toolbar (Dump / Family / Sidecar JSON / IR / Signal / Restart) ----
        bar = tk.Frame(root, bg="#1b1b1b", padx=8, pady=6)
        bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=8, pady=(8, 0))

        tk.Label(bar, text="Dump:", bg="#1b1b1b", fg="#ccc", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.dump_var = tk.StringVar()
        self.dump_combo = ttk.Combobox(bar, textvariable=self.dump_var, width=48,
                                       values=[label for label, _p, _sc in self._catalog])
        self.dump_combo.pack(side=tk.LEFT, padx=(4, 4))
        self.dump_combo.bind("<<ComboboxSelected>>", self._on_dump_selected)
        self.dump_combo.bind("<Return>", self._on_dump_entry_return)

        tk.Button(bar, text="Browse...", bg="#333", fg="white", relief="flat", padx=6,
                  command=self.browse_dump).pack(side=tk.LEFT, padx=(0, 8))

        tk.Label(bar, text="Family:", bg="#1b1b1b", fg="#ccc", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.family_var = tk.StringVar(value=family if family in FAMILIES else "Auto")
        self.family_combo = ttk.Combobox(bar, textvariable=self.family_var, width=8,
                                         values=FAMILIES, state="readonly")
        self.family_combo.pack(side=tk.LEFT, padx=(4, 8))
        self.family_combo.bind("<<ComboboxSelected>>", lambda _e: self.restart_emulation())

        tk.Label(bar, text="JSON:", bg="#1b1b1b", fg="#ccc", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.sidecar_var = tk.StringVar(value=json_path if json_path else SIDECAR_AUTO)
        self.sidecar_combo = ttk.Combobox(bar, textvariable=self.sidecar_var, width=24,
                                          values=list(self._sidecar_presets.keys()))
        self.sidecar_combo.pack(side=tk.LEFT, padx=(4, 4))
        self.sidecar_combo.bind("<<ComboboxSelected>>", lambda _e: self.restart_emulation())

        tk.Button(bar, text="JSON...", bg="#333", fg="white", relief="flat", padx=6,
                  command=self.browse_json).pack(side=tk.LEFT, padx=(0, 8))

        tk.Label(bar, text="IR:", bg="#1b1b1b", fg="#ccc", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self.ir_var = tk.StringVar(value="Auto")
        self.ir_combo = ttk.Combobox(bar, textvariable=self.ir_var, width=8,
                                     values=IR_CODINGS, state="readonly")
        self.ir_combo.pack(side=tk.LEFT, padx=(4, 8))

        self.signal_var = tk.BooleanVar(value=bool(signal))
        tk.Checkbutton(bar, text="Signal + TS", variable=self.signal_var, bg="#1b1b1b", fg="#ccc",
                       selectcolor="#333", activebackground="#1b1b1b", activeforeground="white",
                       command=self._on_signal_toggled).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(bar, text="Restart", bg="#27ae60", fg="white", relief="flat", padx=8,
                  command=self.restart_emulation).pack(side=tk.LEFT)

        self._sync_dump_combo_display()

        # ---- TV screen & UART console ----
        w, h = int(1280 * scale), int(720 * scale)
        self._w, self._h = w, h
        self.cols = (np.arange(w) / scale).astype(int)
        self.rows = (np.arange(h) / scale).astype(int)
        self._flat_idx = (self.rows[:, None] * 1280 + self.cols[None, :]).ravel()
        self._ppm_header = b"P6 %d %d 255\n" % (w, h)
        self._blank_ppm = self._ppm_header + bytes(w * h * 3)
        root.grid_columnconfigure(0, minsize=w + 16, weight=1)
        root.grid_rowconfigure(1, minsize=h + 16, weight=1)
        self.screen = tk.Label(root, bg="black", width=w, height=h)
        self.screen.grid(row=1, column=0, padx=8, pady=8)
        self._show(self._blank_ppm)

        # The UART console: the same place as the screen, shown on demand
        # (F5 / the button under the remote).  Output from the firmware
        # arrives through self.uart; a line typed below goes to its UART.
        self.uart = []
        self._uart_shown = 0
        self.view = "screen"
        self.console = tk.Frame(root, bg="#111")
        self.console.grid(row=1, column=0, padx=8, pady=8, sticky="nsew")
        scroll = tk.Scrollbar(self.console)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.console_text = tk.Text(self.console, wrap="char", bg="black", fg="#9f9", insertbackground="#9f9",
                                    font=("Consolas", 10), state="disabled", yscrollcommand=scroll.set)
        self.console_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        scroll.config(command=self.console_text.yview)
        line = tk.Frame(self.console, bg="#111")
        line.pack(side=tk.BOTTOM, fill=tk.X, pady=(4, 0))
        tk.Label(line, text="UART >", bg="#111", fg="#aaa", font=("Consolas", 10)).pack(side=tk.LEFT)
        self.entry = tk.Entry(line, bg="#222", fg="white", insertbackground="white", font=("Consolas", 10))
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.entry.bind("<Return>", lambda e: self.send_uart())
        tk.Button(line, text="Send", bg="#333", fg="white", relief="flat", command=self.send_uart).pack(side=tk.LEFT)
        self.console.grid_remove()

        # ---- Remote control & front panel ----
        pad = tk.Frame(root, bg="#222", padx=8, pady=8)
        pad.grid(row=1, column=1, sticky="n", padx=(0, 8), pady=8)
        for label, key, r, c in REMOTE:
            if key is None:
                tk.Label(pad, text="", bg="#222").grid(row=r, column=c)
                continue
            tk.Button(pad, text=label, width=6, bg="#333", fg="white", activebackground="#555",
                      relief="flat", command=lambda k=key: self.press(k)).grid(row=r, column=c, padx=2, pady=2)
        cf = tk.Frame(pad, bg="#222")
        cf.grid(row=11, column=0, columnspan=3, pady=(6, 0))
        for i, (key, colour) in enumerate(COLOURS):
            tk.Button(cf, text=" ", width=3, bg=colour, activebackground=colour, relief="flat",
                      command=lambda k=key: self.press(k)).grid(row=0, column=i, padx=2)
        tk.Button(pad, text="Save PNG", bg="#333", fg="white", relief="flat",
                  command=self.save).grid(row=12, column=0, columnspan=3, pady=(10, 0), sticky="ew")
        self.view_button = tk.Button(pad, text="UART console (F5)", bg="#333", fg="white", relief="flat",
                                     command=self.toggle_view)
        self.view_button.grid(row=16, column=0, columnspan=3, pady=(10, 0), sticky="ew")

        # Front panel: the 4-digit LED display and its keys
        self.seg = tk.Canvas(pad, width=4 * 34 + 12, height=58, bg="#111", highlightthickness=0)
        self.seg.grid(row=13, column=0, columnspan=3, pady=(12, 2))
        self._seg_items = []
        for d in range(4):
            ox, oy = 10 + d * 34, 6
            self._seg_items.append([self.seg.create_polygon([(ox + x, oy + y) for x, y in SEG_POLYS[s]],
                                                            fill=SEG_OFF, outline="") for s in range(7)]
                                   + [self.seg.create_oval(ox + 25, oy + 41, ox + 29, oy + 45, fill=SEG_OFF, outline="")])
        self._shown_digits = None
        self.panel_label = tk.Label(pad, text="", bg="#222", fg="#888", wraplength=200,
                                    font=("TkDefaultFont", 7))
        self.panel_label.grid(row=14, column=0, columnspan=3)
        self.pf = tk.Frame(pad, bg="#222")
        self.pf.grid(row=15, column=0, columnspan=3)
        self._apply_sidecar_selection()
        self._rebuild_panel()

        self.status_var = tk.StringVar(value=self.status)
        tk.Label(root, textvariable=self.status_var, anchor="w", bg="#111", fg="#aaa",
                 font=("Consolas", 9)).grid(row=2, column=0, columnspan=2, sticky="ew", padx=8, pady=(0, 6))

        root.bind("<Key>", self.on_key)
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.thread = threading.Thread(target=self.emulate_loop, daemon=True)
        self.thread.start()
        root.after(200, self.refresh)

    # ---- Toolbar & configuration helpers ------------------------------------
    def _sync_dump_combo_display(self):
        self.dump_var.set(dump_catalog.catalog_label_for(self.dump, self._catalog))

    def _apply_sidecar_selection(self):
        dump_catalog.apply_sidecar_selection(self.dump, self.sidecar_var.get(), self._sidecar_presets)

    def _rebuild_panel(self):
        self.panel, self.panel_keys, panel_desc = make_panel(self.dump, log_handler=lambda m: None)
        self.panel.dump_enabled = False
        self._shown_digits = None
        self.panel_label.configure(text="panel: " + panel_desc)
        for child in self.pf.winfo_children():
            child.destroy()
        for i, (label, code) in enumerate(self.panel_keys):
            known = not label[0].isdigit()
            tk.Button(self.pf, text=label, width=4, bg="#4a4a4a" if known else "#2e2e2e",
                      fg="white" if known else "#999", activebackground="#666", relief="flat",
                      font=("TkDefaultFont", 7),
                      command=lambda c=code: self.press_panel(c)).grid(row=i // 4, column=i % 4, padx=1, pady=1)

    def _on_dump_selected(self, _event=None):
        sel = self.dump_var.get()
        path = self._label_to_path.get(sel, sel)
        self.load_dump(path)

    def _on_dump_entry_return(self, _event=None):
        sel = self.dump_var.get().strip()
        path = self._label_to_path.get(sel, sel)
        self.load_dump(path)
        self.root.focus_set()

    def browse_dump(self):
        initial = DUMPS_DIR if os.path.isdir(DUMPS_DIR) else "."
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Select Firmware Image (.bin / .abs)",
            initialdir=initial,
            filetypes=[("Firmware images", "*.bin *.abs *.rom"), ("All files", "*.*")],
        )
        if path:
            self.load_dump(path)

    def browse_json(self):
        initial = os.path.dirname(resolve_dump(self.dump)) if os.path.exists(resolve_dump(self.dump)) else DUMPS_DIR
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Select Sidecar JSON (.json)",
            initialdir=initial,
            filetypes=[("Sidecar JSON", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.sidecar_var.set(path)
            self.restart_emulation()

    def load_dump(self, dump_path):
        self.dump = dump_catalog.resolve_catalog_dump(dump_path, self._catalog)
        self._sync_dump_combo_display()
        self.restart_emulation()

    def _on_signal_toggled(self):
        self.keys.put(("__signal__", bool(self.signal_var.get())))

    def restart_emulation(self):
        self._apply_sidecar_selection()
        self._rebuild_panel()
        self.root.title(f"AliSimulator TV - {os.path.basename(self.dump)}")
        # Clear console and screen
        self.uart.clear()
        self._uart_shown = 0
        self.console_text.configure(state="normal")
        self.console_text.delete("1.0", tk.END)
        self.console_text.configure(state="disabled")
        self._show(self._blank_ppm)
        while not self.keys.empty():
            try:
                self.keys.get_nowait()
            except queue.Empty:
                break
        self.status = "restarting..."
        self._reload_requested = True
        sim = self._current_sim
        if sim is not None and sim.mu is not None:
            try:
                sim.mu.emu_stop()
            except Exception:
                pass
        self.root.focus_set()

    # ---- GUI thread ---------------------------------------------------------
    def _to_ppm(self, rgb):
        if rgb.shape[:2] == (720, 1280):
            return self._ppm_header + rgb.view("V3").ravel()[self._flat_idx].tobytes()
        scaled = np.ascontiguousarray(rgb[self.rows][:, self.cols])
        h, w = scaled.shape[:2]
        return b"P6 %d %d 255\n" % (w, h) + scaled.tobytes()

    def _show(self, data):
        ppm = data if isinstance(data, (bytes, bytearray)) else self._to_ppm(data)
        img = tk.PhotoImage(data=ppm, format="PPM")
        self.screen.configure(image=img, width=self._w, height=self._h)
        self.screen.image = img

    def refresh(self):
        if self.frame is not None:
            self._show(self.frame)
            self.frame = None
        digits = tuple(self.panel.digits)
        if digits != self._shown_digits:
            self._shown_digits = digits
            for d, items in enumerate(self._seg_items):
                v = digits[d] if digits else 0
                for s, item in enumerate(items):
                    self.seg.itemconfigure(item, fill=SEG_ON if v >> s & 1 else SEG_OFF)
        n = len(self.uart)
        if n > self._uart_shown:
            text = "".join(self.uart[self._uart_shown:n]).replace("\r", "")
            text = ANSI_ESCAPE.sub("", text).translate(_CTRL_TRANS)
            self._uart_shown = n
            self.console_text.configure(state="normal")
            self.console_text.insert(tk.END, text)
            self.console_text.configure(state="disabled")
            if self.view == "console":
                self.console_text.see(tk.END)
        st = self.status
        if st != self._shown_status:
            self._shown_status = st
            self.status_var.set(st)
        if not self.stop:
            self.root.after(100, self.refresh)

    def on_key(self, event):
        if event.keysym == "F5":
            self.toggle_view()
            return
        focused = self.root.focus_get()
        if focused in (self.entry, self.dump_combo, self.family_combo, self.sidecar_combo, self.ir_combo):
            return                          # typing in an input / combobox, not remote keys
        key = KEYMAP.get(event.keysym) or (event.char if event.char.isdigit() else None)
        if key:
            self.press(key)

    def toggle_view(self):
        if self.view == "screen":
            self.view = "console"
            self.screen.grid_remove()
            self.console.grid()
            self.console_text.see(tk.END)
            self.view_button.configure(text="TV screen (F5)")
            self.entry.focus_set()
        else:
            self.view = "screen"
            self.console.grid_remove()
            self.screen.grid()
            self.view_button.configure(text="UART console (F5)")
            self.root.focus_set()

    def send_uart(self):
        line = self.entry.get()
        self.entry.delete(0, tk.END)
        self.keys.put(("__uart__", line + "\r\n"))

    def press(self, key):
        self.keys.put(key)

    def press_panel(self, code):
        self.panel.press_key(code)              # answered by the next key read (one key event)

    def save(self):
        self.keys.put("__save__")

    def close(self):
        self.stop = True
        sim = self._current_sim
        if sim is not None and sim.mu is not None:
            try:
                sim.mu.emu_stop()
            except Exception:
                pass
        self.root.after(300, self.root.destroy)

    # ---- emulation thread ---------------------------------------------------
    def emulate_loop(self):
        while not self.stop:
            self._reload_requested = False
            self.emulate_one()
            sim = self._current_sim
            self._current_sim = None
            if sim is not None and getattr(sim, "_stopper", None) is not None:
                try:
                    sim._stopper.close()
                except Exception:
                    pass
            while not self.stop and not self._reload_requested:
                time.sleep(0.05)

    def emulate_one(self):
        dump = self.dump
        fam_sel = self.family_var.get()
        chip_arg = None if fam_sel == "Auto" else fam_sel
        try:
            sim = AliMipsSimulator(rom_size=flash_size_for(dump), log_handler=lambda m: None)
            self._current_sim = sim
            sim.lzma_insns_per_byte = 0             # the bootloader's unpacking costs no firmware time here
            sim.setSPIDump(False)
            sim.setI2CDump(False)
            uart = self.uart
            sim.setUartHandler(lambda c: uart.append(c))
            panel = self.panel
            sim.setGpioHandler(panel.on_gpio_write)
            sim.loadFile(dump, chip=chip_arg)
            if self.signal_var.get():
                sim.set_signal(True)
                sim.attach_mux()
            else:
                sim.attach_tuner()
        except Exception as e:
            self.status = f"LOAD FAILED ({os.path.basename(dump)}): {e!r}"
            return

        t0 = time.time()
        shown_ops, shown_at, last_ops, note, app = -1, 0.0, 0, "", False
        chip_id = int.from_bytes(sim._mmio_view[2:4], "little")
        chip_tag = f"{sim.chip.name} (0x{chip_id:04X})"
        while not self.stop and not self._reload_requested:
            w0, v0 = time.time(), sim._vtime()
            try:
                # A quarter of a second of the firmware's time per step, and no
                # faster than real time: the simulator skips the time an idle
                # firmware waits for its next tick (idle_skip), which would run
                # its clock and animations ahead of the wall clock.
                sim.run(max_instructions=sim.instruction_count + 2_000_000, max_vtime=v0 + 0.25)
            except Exception as e:
                if self._reload_requested or self.stop:
                    return
                # keep the window (and its last frame) alive, show what happened
                self.status = f"{time.time() - t0:6.0f}s  [{chip_tag}]  EMULATION STOPPED: {e!r}"
                return
            if self._reload_requested or self.stop:
                return
            ahead = (sim._vtime() - v0) - (time.time() - w0)
            if ahead > 0:
                time.sleep(min(ahead, 0.25))
            while not self.keys.empty():
                key = self.keys.get()
                try:
                    if key == "__save__":
                        path = os.path.abspath(f"tv_{time.strftime('%H%M%S')}.png")
                        sim.capture_screen(path)
                        note = f"saved {path}"
                    elif isinstance(key, tuple) and key[0] == "__uart__":
                        sim.setUartReceiveData(key[1].encode("latin-1", "replace"))
                        note = f"UART <- {key[1].strip()!r}"
                    elif isinstance(key, tuple) and key[0] == "__signal__":
                        on = key[1]
                        sim.set_signal(on)
                        if on:
                            sim.attach_mux()
                            note = "signal + TS mux ON"
                        else:
                            sim.attach_tuner()
                            note = "signal OFF"
                    else:
                        ir_sel = self.ir_var.get()
                        coding = None if ir_sel == "Auto" else ir_sel
                        a, c = sim.press_key(key, coding=coding)
                        used = coding or sim.ir_coding
                        note = f"key {key} ({used} 0x{a:02X}/0x{c:02X})"
                except Exception as e:
                    note = f"key {key}: {e}"
            # Redraw once the GE has finished drawing (no new commands this
            # slice), and while it keeps drawing at least every REFRESH_S; for
            # CPU-drawn OSDs where sim.ge_ops stays 0 (e.g. M3329), also
            # refresh periodically every CPU_OSD_REFRESH_S once booted.
            now = time.time()
            drawing = sim.ge_ops != last_ops
            ge_ready = sim.ge_ops != shown_ops and (not drawing or now - shown_at >= REFRESH_S)
            cpu_osd_ready = sim.ge_ops == 0 and sim.instruction_count >= 2_000_000 and now - shown_at >= CPU_OSD_REFRESH_S
            if ge_ready or cpu_osd_ready:
                shown_ops, shown_at = sim.ge_ops, now
                try:
                    rgb = sim.capture_screen()
                    self.frame = self._to_ppm(rgb)
                except Exception as e:
                    note = f"capture: {e}"
            last_ops = sim.ge_ops
            app = app or "Application version" in "".join(uart[-400:]) or sim.ge_ops > 0
            phase = "application running" if app else "booting"
            queued = len(sim._irc_frames)
            ir_sel = self.ir_var.get()
            ir_used = sim.ir_coding if ir_sel == "Auto" else ir_sel
            tinfo = sim.tuner_info()
            tuner_str = f"  [{tinfo}]" if tinfo and not tinfo.endswith(": not tuned") else ""
            self.status = (f"{now - t0:6.0f}s  [{chip_tag} | ir:{ir_used}]  {phase}  "
                           f"GE {sim.ge_ops}{' (drawing)' if drawing else ''}  "
                           f"IR {sim.ir_keys_sent}{f' +{queued} queued' if queued else ''}"
                           f"{tuner_str}  {note}")


def main():
    args = sys.argv[1:]
    scale = 0.75
    family = "Auto"
    json_path = None
    signal = False
    if "--scale" in args:
        i = args.index("--scale")
        scale = float(args[i + 1])
        del args[i:i + 2]
    if "--family" in args:
        i = args.index("--family")
        family = args[i + 1]
        del args[i:i + 2]
    if "--json" in args:
        i = args.index("--json")
        json_path = args[i + 1]
        del args[i:i + 2]
    if "--signal" in args:
        args.remove("--signal")
        signal = True
    dump = args[0] if args else "dump_maciej.bin"
    root = tk.Tk()
    TvGui(root, dump, scale, family=family, json_path=json_path, signal=signal)
    root.mainloop()


if __name__ == "__main__":
    main()
