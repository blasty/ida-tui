#!/usr/bin/env python3
"""Regenerate logo.ans (the block-art splash) from logo.png.

logo.ans is the fallback for terminals that can't draw an image, so it has to be
rendered from the same artwork or the two drift apart -- which is exactly what
happened when logo.png was replaced and the old block art kept a scan line that
no longer existed.

Each cell is a lower half-block: the background colour paints the upper pixel,
the foreground the lower one, so one cell carries two pixel rows. Transparent
pixels emit no colour at all, letting the terminal background show through, and
a cell whose lower pixel is transparent uses an upper half-block instead so the
one opaque pixel still lands on the correct half.

Needs Pillow, so run it with a python that has it (NOT ~/ida-venv):

    /usr/bin/python3 tools/make_logo_ans.py [--cols 60] [-o logo.ans]
"""

from __future__ import annotations

import argparse
import os
import sys

from PIL import Image

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALPHA_ON = 128  # at/above this a pixel counts as present

UPPER, LOWER = "\u2580", "\u2584"  # upper half block, lower half block


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--png", default=os.path.join(REPO, "logo.png"))
    ap.add_argument("-o", "--out", default=os.path.join(REPO, "logo.ans"))
    ap.add_argument("--cols", type=int, default=60)
    ap.add_argument(
        "--cell",
        default="9x22",
        help="terminal cell size WxH in px, for the aspect ratio",
    )
    args = ap.parse_args()

    cw, ch = (int(v) for v in args.cell.lower().split("x"))
    im = Image.open(args.png).convert("RGBA")
    bbox = im.getchannel("A").getbbox()
    if bbox:
        im = im.crop(bbox)
    w, h = im.size
    cols = args.cols
    # two pixel rows per cell, and cells are taller than they are wide
    rows = max(1, round((h / w) * cols * cw / ch))
    im = im.resize((cols, rows * 2), Image.LANCZOS)
    px = im.load()

    out: list[str] = []
    for r in range(rows):
        line = []
        prev = None
        for c in range(cols):
            top = px[c, r * 2]
            bot = px[c, r * 2 + 1]
            t_on, b_on = top[3] >= ALPHA_ON, bot[3] >= ALPHA_ON
            if not t_on and not b_on:
                sgr, ch_ = "\033[0m", " "
            elif t_on and b_on:
                sgr = (
                    f"\033[38;2;{bot[0]};{bot[1]};{bot[2]}m"
                    f"\033[48;2;{top[0]};{top[1]};{top[2]}m"
                )
                ch_ = LOWER
            elif b_on:  # only the lower pixel is present
                sgr = f"\033[0m\033[38;2;{bot[0]};{bot[1]};{bot[2]}m"
                ch_ = LOWER
            else:  # only the upper pixel is present
                sgr = f"\033[0m\033[38;2;{top[0]};{top[1]};{top[2]}m"
                ch_ = UPPER
            if sgr != prev:
                line.append(sgr)
                prev = sgr
            line.append(ch_)
        line.append("\033[0m")
        out.append("".join(line))

    text = "\n".join(out) + "\n"
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(text)
    print(
        f"{args.png} {w}x{h} -> {args.out}  {cols}x{rows} cells "
        f"({len(text):,} bytes, cell {cw}x{ch})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
