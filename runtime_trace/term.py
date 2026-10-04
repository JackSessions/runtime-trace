"""Terminal niceties: colour and real ASCII-art banners, in the same Google-colour identity as this author's
other DFIR tools (the shield, the glowing buttons, PhantomTrace's own figlet wordmark). Switches itself off
for pipes, NO_COLOR and --no-color."""
from __future__ import annotations

import os
import sys

GOOGLE = {"blue": "38;2;66;133;244", "red": "38;2;234;67;53", "yellow": "38;2;251;188;4", "green": "38;2;52;168;83"}
# consistency.verdict() returns one of exactly these four names (also used as report.py's CSS class names);
# "cyan" is kept as the canonical name for the low-confidence tier across both, and mapped to Google blue here.
CODES = {**GOOGLE, "cyan": GOOGLE["blue"], "dim": "2", "bold": "1"}
_CYCLE = ["blue", "red", "yellow", "green"]

# The wordmark (figlet, font "small", same family as PhantomTrace's own banner). Plain ASCII, no box-drawing:
# this is the one piece of "awesome in the terminal" that is pure text art, so it is exactly as portable as
# the rest of the CLI, and reads fine even with colour off or piped to a file.
WORDMARK = [
    r" ___          _   _          _____                ",
    r"| _ \_  _ _ _| |_(_)_ __  __|_   _| _ __ _ __ ___ ",
    r"|   / || | ' \  _| | '  \/ -_)| || '_/ _` / _/ -_)",
    r"|_|_\\_,_|_||_\__|_|_|_|_\___||_||_| \__,_\__\___|",
]
SUBTITLE = "runtime cross-layer consistency checker, via eBPF"
BANNER = "\n".join(f"  {ln}" for ln in WORDMARK)          # the wordmark alone; callers add the subtitle/version line


def _box(*lines: str, pad: str = "  ") -> str:
    """Builds a box-drawing frame sized to its own longest line, so it can never go out of alignment."""
    width = max(len(ln) for ln in lines) + 2
    top, bottom = f"{pad}┌{'─' * width}┐", f"{pad}└{'─' * width}┘"
    middle = "\n".join(f"{pad}│ {ln.ljust(width - 1)}│" for ln in lines)
    return f"{top}\n{middle}\n{bottom}"


# --pretty wraps the same wordmark in a box-drawing frame (plain UTF-8, no ANSI of its own, fine in a
# terminal, a file or a pipe); only the colour wrapped around it switches off for NO_COLOR etc.
BANNER_PRETTY = _box(*WORDMARK, "", SUBTITLE)

SEV_COLOR = {"high": "red", "medium": "yellow", "low": "blue"}


def bar(n: int, cap: int = 20) -> str:
    """A small block-character bar for --pretty: length shows magnitude, not a precise proportion."""
    filled = min(cap, n)
    return "█" * filled + "░" * (cap - filled)


class Style:
    def __init__(self, on: bool) -> None:
        self.on = on

    def __call__(self, name: str, text: str) -> str:
        if not self.on:
            return text
        code = CODES.get(name)                           # an unrecognised name degrades to plain text,
        return f"\x1b[{code}m{text}\x1b[0m" if code else text   # never a crash: a missing colour is cosmetic

    def google(self, text: str) -> str:
        """Each line gets the next Google colour in turn; used for the plain box borders in --pretty."""
        if not self.on:
            return text
        out = []
        for i, line in enumerate(text.split("\n")):
            out.append(self(_CYCLE[i % len(_CYCLE)], line) if line.strip() else line)
        return "\n".join(out)

    def wordmark(self, text: str) -> str:
        """A diagonal, four-colour cycle across every non-space character, the same spirit as PhantomTrace's
        own rainbow banner but in the Google palette rather than a full hue spectrum, so the two tools read as
        a family rather than identical twins. Falls back to plain text with colour off."""
        if not self.on:
            return text
        out = []
        for row, line in enumerate(text.split("\n")):
            chars = []
            for col, ch in enumerate(line):
                if ch == " ":
                    chars.append(ch)
                    continue
                chars.append(self(_CYCLE[(col // 3 + row) % len(_CYCLE)], ch))
            out.append("".join(chars))
        return "\n".join(out)


def color_ok(no_color_flag: bool = False) -> bool:
    return sys.stdout.isatty() and not no_color_flag and "NO_COLOR" not in os.environ


def enable_windows_ansi() -> None:
    if os.name == "nt":
        os.system("")
