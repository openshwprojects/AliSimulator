"""
Interactive "TV": boots a firmware dump in the simulator, shows what its OSD
draws (live, through the GE model and the GMA display layer) and lets you
drive the menus with a virtual IR remote control.

    python tv_gui.py [dump_maciej.bin] [--scale 0.75]

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

import numpy as np

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

# Front panel: the dump's LED-driver chip (front_panel.py: a TM1650 on I2C or
# a TM1628-class 3-wire chip, each on its bit-bang GPIO pins) drives a 4-digit
# 7-segment display and scans a key matrix.  The buttons below the display
# press each matrix position; dump_maciej's panel driver reacts to KI1/DIG4
# (up / CH+) and KI2/DIG4 (down / CH-) only (every code was tried on its
# wizard).  A board without the chip shows a blank display and ignores them.
# 7-segment layout: bit0..6 = segments a (top), b, c, d (bottom), e, f, g (middle), bit7 = DP
SEG_POLYS = {
    0: [(3, 0), (19, 0), (17, 3), (5, 3)],
    1: [(20, 1), (23, 4), (23, 18), (20, 21), (18, 18), (18, 4)],
    2: [(20, 23), (23, 26), (23, 40), (20, 43), (18, 40), (18, 26)],
    3: [(3, 44), (19, 44), (17, 41), (5, 41)],
    4: [(0, 23), (3, 26), (3, 40), (0, 43), (-2, 40), (-2, 26)],
    5: [(0, 1), (3, 4), (3, 18), (0, 21), (-2, 18), (-2, 4)],
    6: [(3, 22), (19, 22), (17, 24), (5, 24), (3, 22), (5, 20), (17, 20), (19, 22)],
}
SEG_ON, SEG_OFF = "#ff3b30", "#2a1210"

# (label, key name, grid row, column) of the on-screen remote
REMOTE = [
    ("POWER", "POWER", 0, 0), ("MENU", "MENU", 0, 1), ("EXIT", "EXIT", 0, 2),
    ("", None, 1, 0), ("\u25b2", "UP", 1, 1), ("", None, 1, 2),
    ("\u25c0", "LEFT", 2, 0), ("OK", "OK", 2, 1), ("\u25b6", "RIGHT", 2, 2),
    ("", None, 3, 0), ("\u25bc", "DOWN", 3, 1), ("", None, 3, 2),
    ("1", "1", 4, 0), ("2", "2", 4, 1), ("3", "3", 4, 2),
    ("4", "4", 5, 0), ("5", "5", 5, 1), ("6", "6", 5, 2),
    ("7", "7", 6, 0), ("8", "8", 6, 1), ("9", "9", 6, 2),
    ("INFO", "INFO", 7, 0), ("0", "0", 7, 1), ("EPG", "EPG", 7, 2),
    ("CH+", "CH+", 8, 0), ("VOL+", "VOL+", 8, 1), ("FAV", "FAV", 8, 2),
    ("CH-", "CH-", 9, 0), ("VOL-", "VOL-", 9, 1), ("MUTE", "MUTE", 9, 2),
]
COLOURS = [("RED", "#c0392b"), ("GREEN", "#27ae60"), ("YELLOW", "#d4ac0d"), ("BLUE", "#2471a3")]
REFRESH_S = 1.5         # screen refresh interval while the GE keeps drawing
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
KEYMAP = {
    "Up": "UP", "Down": "DOWN", "Left": "LEFT", "Right": "RIGHT", "Return": "OK",
    "KP_Enter": "OK", "Escape": "EXIT", "BackSpace": "EXIT", "m": "MENU", "i": "INFO",
    "Prior": "CH+", "Next": "CH-", "plus": "VOL+", "minus": "VOL-", "KP_Add": "VOL+",
    "KP_Subtract": "VOL-", "F1": "RED", "F2": "GREEN", "F3": "YELLOW", "F4": "BLUE",
    "e": "EPG", "p": "POWER",
}


class TvGui:
    def __init__(self, root, dump, scale):
        self.root, self.dump, self.scale = root, dump, scale
        self.keys = queue.Queue()
        self.frame = None               # newest PPM image from the emulation thread
        self.status = "booting..."
        self.stop = False
        root.title(f"AliSimulator TV - {dump}")
        root.configure(bg="#111")

        w, h = int(1280 * scale), int(720 * scale)
        self.cols = (np.arange(w) / scale).astype(int)
        self.rows = (np.arange(h) / scale).astype(int)
        root.grid_columnconfigure(0, minsize=w + 16)
        root.grid_rowconfigure(0, minsize=h + 16)
        self.screen = tk.Label(root, bg="black", width=w, height=h)
        self.screen.grid(row=0, column=0, padx=8, pady=8)
        self._show(np.zeros((h, w, 3), np.uint8))

        # The UART console: the same place as the screen, shown on demand
        # (F5 / the button under the remote).  Output from the firmware
        # arrives through self.uart; a line typed below goes to its UART.
        self.uart = []
        self._uart_shown = 0
        self.view = "screen"
        self.console = tk.Frame(root, bg="#111")
        self.console.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")
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

        pad = tk.Frame(root, bg="#222", padx=8, pady=8)
        pad.grid(row=0, column=1, sticky="n", padx=(0, 8), pady=8)
        for label, key, r, c in REMOTE:
            if key is None:
                tk.Label(pad, text="", bg="#222").grid(row=r, column=c)
                continue
            tk.Button(pad, text=label, width=6, bg="#333", fg="white", activebackground="#555",
                      relief="flat", command=lambda k=key: self.press(k)).grid(row=r, column=c, padx=2, pady=2)
        cf = tk.Frame(pad, bg="#222")
        cf.grid(row=10, column=0, columnspan=3, pady=(6, 0))
        for i, (key, colour) in enumerate(COLOURS):
            tk.Button(cf, text=" ", width=3, bg=colour, activebackground=colour, relief="flat",
                      command=lambda k=key: self.press(k)).grid(row=0, column=i, padx=2)
        tk.Button(pad, text="Save PNG", bg="#333", fg="white", relief="flat",
                  command=self.save).grid(row=11, column=0, columnspan=3, pady=(10, 0), sticky="ew")
        self.view_button = tk.Button(pad, text="UART console (F5)", bg="#333", fg="white", relief="flat",
                                     command=self.toggle_view)
        self.view_button.grid(row=15, column=0, columnspan=3, pady=(10, 0), sticky="ew")

        # Front panel: the 4-digit LED display and its keys
        self.panel, self.panel_keys, panel_desc = make_panel(dump, log_handler=lambda m: None)
        self.panel.dump_enabled = False
        self.seg = tk.Canvas(pad, width=4 * 34 + 12, height=58, bg="#111", highlightthickness=0)
        self.seg.grid(row=12, column=0, columnspan=3, pady=(12, 2))
        self._seg_items = []
        for d in range(4):
            ox, oy = 10 + d * 34, 6
            self._seg_items.append([self.seg.create_polygon([(ox + x, oy + y) for x, y in SEG_POLYS[s]],
                                                            fill=SEG_OFF, outline="") for s in range(7)]
                                   + [self.seg.create_oval(ox + 25, oy + 41, ox + 29, oy + 45, fill=SEG_OFF, outline="")])
        self._shown_digits = None
        tk.Label(pad, text="panel: " + panel_desc, bg="#222", fg="#888", wraplength=200,
                 font=("TkDefaultFont", 7)).grid(row=13, column=0, columnspan=3)
        pf = tk.Frame(pad, bg="#222")
        pf.grid(row=14, column=0, columnspan=3)
        for i, (label, code) in enumerate(self.panel_keys):
            known = not label[0].isdigit()
            tk.Button(pf, text=label, width=4, bg="#4a4a4a" if known else "#2e2e2e", fg="white" if known else "#999",
                      activebackground="#666", relief="flat", font=("TkDefaultFont", 7),
                      command=lambda c=code: self.press_panel(c)).grid(row=i // 4, column=i % 4, padx=1, pady=1)

        self.status_var = tk.StringVar(value=self.status)
        tk.Label(root, textvariable=self.status_var, anchor="w", bg="#111", fg="#aaa",
                 font=("Consolas", 9)).grid(row=1, column=0, columnspan=2, sticky="ew", padx=8, pady=(0, 6))

        root.bind("<Key>", self.on_key)
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.thread = threading.Thread(target=self.emulate, daemon=True)
        self.thread.start()
        root.after(200, self.refresh)

    # ---- GUI thread ---------------------------------------------------------
    def _show(self, rgb):
        h, w = rgb.shape[:2]
        img = tk.PhotoImage(data=b"P6 %d %d 255\n" % (w, h) + rgb.tobytes(), format="PPM")
        self.screen.configure(image=img, width=w, height=h)
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
            text = ANSI_ESCAPE.sub("", text)        # the console clears the terminal with ESC[H ESC[2J
            text = "".join(c if c >= " " or c in "\n\t" else "·" for c in text)
            self._uart_shown = n
            self.console_text.configure(state="normal")
            self.console_text.insert(tk.END, text)
            self.console_text.configure(state="disabled")
            if self.view == "console":
                self.console_text.see(tk.END)
        self.status_var.set(self.status)
        if not self.stop:
            self.root.after(100, self.refresh)

    def on_key(self, event):
        if event.keysym == "F5":
            self.toggle_view()
            return
        if self.root.focus_get() is self.entry:
            return                          # typing a UART line, not remote keys
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
        self.root.after(300, self.root.destroy)

    # ---- emulation thread ---------------------------------------------------
    def emulate(self):
        sim = AliMipsSimulator(rom_size=flash_size_for(self.dump), log_handler=lambda m: None)
        sim.setSPIDump(False)
        sim.setI2CDump(False)
        uart = self.uart
        sim.setUartHandler(lambda c: uart.append(c))
        sim.setGpioHandler(self.panel.on_gpio_write)
        sim.loadFile(self.dump)
        t0 = time.time()
        shown_ops, shown_at, last_ops, note, app = -1, 0.0, 0, "", False
        while not self.stop:
            try:
                sim.run(max_instructions=sim.instruction_count + 2_000_000)
            except Exception as e:
                # keep the window (and its last frame) alive, show what happened
                self.status = f"{time.time() - t0:6.0f}s  EMULATION STOPPED: {e!r}"
                return
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
                    else:
                        a, c = sim.press_key(key)
                        note = f"key {key} (NEC 0x{a:02X}/0x{c:02X})"
                except Exception as e:
                    note = f"key {key}: {e}"
            # Redraw once the GE has finished drawing (no new commands this
            # slice), and while it keeps drawing at least every REFRESH_S: a
            # redraw costs the firmware seconds of emulated time (hundreds of
            # GE commands), and a progress screen (the channel search) never
            # goes quiet at all.
            drawing = sim.ge_ops != last_ops
            if sim.ge_ops != shown_ops and (not drawing or time.time() - shown_at >= REFRESH_S):
                shown_ops, shown_at = sim.ge_ops, time.time()
                try:
                    rgb = sim.capture_screen()
                    self.frame = np.ascontiguousarray(rgb[self.rows][:, self.cols])
                except Exception as e:
                    note = f"capture: {e}"
            last_ops = sim.ge_ops
            app = app or "Application version" in "".join(uart[-400:])
            phase = "application running" if app else "booting"
            queued = len(sim._irc_frames)
            self.status = (f"{time.time() - t0:6.0f}s  {phase}  GE commands {sim.ge_ops}"
                           f"{' (drawing)' if drawing else ''}  IR frames {sim.ir_keys_sent}"
                           f"{f' +{queued} queued' if queued else ''}  {note}")


def main():
    args = sys.argv[1:]
    scale = 0.75
    if "--scale" in args:
        i = args.index("--scale")
        scale = float(args[i + 1])
        del args[i:i + 2]
    dump = args[0] if args else "dump_maciej.bin"
    root = tk.Tk()
    TvGui(root, dump, scale)
    root.mainloop()


if __name__ == "__main__":
    main()
