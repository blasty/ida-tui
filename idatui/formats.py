"""Recognising what a file is, and what to ask when we can't.

IDA picks a loader by looking at the file. When one matches, it knows the
processor, the load address and often the entry point, and there is nothing to
ask. When none matches — a raw firmware dump, a flash image, a decompressed blob
— IDA falls back to a plain binary load: **x86 at address 0**. That is a silent
wrong answer, not an error; the database opens, analysis runs, and finds nothing.

Interactive IDA handles this by asking. This module is the "should we ask, and
what are the sensible answers" half of doing the same.

The sniff deliberately only recognises formats IDA definitely has a loader for.
Being wrong in the cautious direction costs one dismissible dialog; being wrong
the other way is the silent-nothing case we're trying to kill.
"""

from __future__ import annotations

import os

#: (magic, offset, name) for formats IDA loads without help.
_MAGIC: tuple[tuple[bytes, int, str], ...] = (
    (b"\x7fELF", 0, "ELF"),
    (b"MZ", 0, "PE/MZ"),
    (b"\xfe\xed\xfa\xce", 0, "Mach-O"),
    (b"\xfe\xed\xfa\xcf", 0, "Mach-O 64"),
    (b"\xce\xfa\xed\xfe", 0, "Mach-O (LE)"),
    (b"\xcf\xfa\xed\xfe", 0, "Mach-O 64 (LE)"),
    (b"\xca\xfe\xba\xbe", 0, "Mach-O fat/Java class"),
    (b"dex\n", 0, "Dalvik"),
    (b"\x00asm", 0, "WebAssembly"),
    (b"!<arch>", 0, "ar archive"),
    (b"\x4c\x01", 0, "COFF i386"),
    (b"\x64\x86", 0, "COFF x64"),
    (b"\x00\x00\x03\xf3", 0, "Amiga hunk"),
    (b"\x7fCGC", 0, "CGC"),
)

#: Text-ish container formats: recognised by their first line, not a magic word.
_TEXT_PREFIX: tuple[tuple[bytes, str], ...] = (
    (b":", "Intel HEX"),
    (b"S0", "Motorola S-record"),
    (b"S1", "Motorola S-record"),
    (b"S2", "Motorola S-record"),
    (b"S3", "Motorola S-record"),
)


def sniff(path: str) -> str | None:
    """The container format of ``path``, or None when nothing recognises it.

    None is the interesting answer: it means IDA will guess, and its guess is
    x86-at-zero regardless of what the bytes actually are.
    """
    try:
        with open(path, "rb") as f:
            head = f.read(64)
    except OSError:
        return None
    if not head:
        return None
    for magic, off, name in _MAGIC:
        if head[off:off + len(magic)] == magic:
            return name
    # Only treat a text prefix as a format if the whole head is printable —
    # a raw blob starting with 0x3a (':') is far more likely than Intel HEX.
    if all(32 <= b < 127 or b in (9, 10, 13) for b in head):
        for prefix, name in _TEXT_PREFIX:
            if head.startswith(prefix):
                return name
    return None


def needs_load_options(path: str) -> bool:
    """True when we should ask how to load ``path`` rather than let IDA guess."""
    return os.path.isfile(path) and sniff(path) is None


#: Processors worth offering, as (IDA -p name, human label).
#:
#: IDA ships 73 processor modules, most of which are museum pieces; a list that
#: long is a worse answer than a short one plus free text. These are the targets
#: that actually turn up in firmware work, endianness spelled out because
#: getting it wrong is the most common way to end up with zero functions.
PROCESSORS: tuple[tuple[str, str], ...] = (
    ("arm", "ARM / AArch64 — little-endian"),
    ("armb", "ARM — big-endian"),
    ("metapc", "x86 / x86-64"),
    ("mipsl", "MIPS — little-endian"),
    ("mipsb", "MIPS — big-endian"),
    ("ppc", "PowerPC — big-endian"),
    ("ppcl", "PowerPC — little-endian"),
    ("sh4", "SuperH SH-4"),
    ("68k", "Motorola 68000"),
    ("riscv", "RISC-V"),
    ("tricore", "Infineon TriCore"),
    ("xtensa", "Tensilica Xtensa (ESP32 etc.)"),
    ("avr", "Atmel AVR"),
    ("z80", "Zilog Z80"),
    ("tms320c6", "TI TMS320C6x DSP"),
    ("m32r", "Renesas M32R"),
    ("arc", "Synopsys ARC"),
    ("h8", "Renesas H8"),
    ("sparc", "SPARC"),
    ("s390", "IBM S/390"),
)


def load_args(processor: str = "", base: int = 0, extra: str = "") -> str:
    """``processor``/``base`` as IDA command-line switches.

    ``-b`` is in PARAGRAPHS, not bytes: ``-b1000`` loads at 0x10000. Every caller
    goes through here so that conversion is done in exactly one place.
    """
    parts = []
    if processor:
        parts.append(f"-p{processor}")
    if base:
        parts.append(f"-b{int(base) >> 4:x}")
    if extra:
        parts.append(extra)
    return " ".join(parts)
