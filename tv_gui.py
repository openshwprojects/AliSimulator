"""
Interactive "TV": boots a firmware dump in the simulator, shows what its OSD
draws (live, through the GE model and the GMA display layer) and lets you
drive the menus with a virtual IR remote control.

    python tv_gui.py [dump_maciej.bin] [--scale 0.75]

Keyboard: arrows, Enter = OK, Esc / Backspace = EXIT, M = MENU, I = INFO,
0-9, PgUp / PgDn = CH+ / CH-, +/- = VOL, F1-F4 = red / green / yellow / blue.

The keys go through the emulated M6303 IR receiver as NEC frames: the
firmware's own interrupt handler, NEC decoder and key table turn them into
UI key messages (see ir_remote.py and AliMipsSimulator.press_key).  The
remote works once the application is up (dump_maciej: the first screen is
drawn about 3 minutes after the start).
"""
import os
import queue
import sys
import threading
import time
import tkinter as tk

import numpy as np

from simulator import AliMipsSimulator

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
        self.screen = tk.Label(root, bg="black", width=w, height=h)
        self.screen.grid(row=0, column=0, padx=8, pady=8)
        self._show(np.zeros((h, w, 3), np.uint8))

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
        self.status_var.set(self.status)
        if not self.stop:
            self.root.after(100, self.refresh)

    def on_key(self, event):
        key = KEYMAP.get(event.keysym) or (event.char if event.char.isdigit() else None)
        if key:
            self.press(key)

    def press(self, key):
        self.keys.put(key)

    def save(self):
        self.keys.put("__save__")

    def close(self):
        self.stop = True
        self.root.after(300, self.root.destroy)

    # ---- emulation thread ---------------------------------------------------
    def emulate(self):
        sim = AliMipsSimulator(log_handler=lambda m: None)
        sim.setSPIDump(False)
        sim.setI2CDump(False)
        uart = []
        sim.setUartHandler(lambda c: uart.append(c))
        sim.loadFile(self.dump)
        t0 = time.time()
        shown_ops, last_ops, note, app = -1, 0, "", False
        while not self.stop:
            sim.run(max_instructions=sim.instruction_count + 2_000_000)
            while not self.keys.empty():
                key = self.keys.get()
                try:
                    if key == "__save__":
                        path = os.path.abspath(f"tv_{time.strftime('%H%M%S')}.png")
                        sim.capture_screen(path)
                        note = f"saved {path}"
                    else:
                        a, c = sim.press_key(key)
                        note = f"key {key} (NEC 0x{a:02X}/0x{c:02X})"
                except Exception as e:
                    note = f"key {key}: {e}"
            # redraw once the GE has finished drawing (no new commands this slice)
            if sim.ge_ops == last_ops and sim.ge_ops != shown_ops:
                shown_ops = sim.ge_ops
                try:
                    rgb = sim.capture_screen()
                    self.frame = np.ascontiguousarray(rgb[self.rows][:, self.cols])
                except Exception as e:
                    note = f"capture: {e}"
            last_ops = sim.ge_ops
            app = app or "Application version" in "".join(uart[-400:])
            phase = "application running" if app else "booting"
            self.status = (f"{time.time() - t0:6.0f}s  {phase}  GE commands {sim.ge_ops}  "
                           f"IR frames {sim.ir_keys_sent}  {note}")


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
