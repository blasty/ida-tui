#!/usr/bin/env python3
"""Format sniffing + load-switch construction (pure stdlib, no IDA)."""

#: format sniffing + load switches, pure stdlib.
#: Read by tests/run.py (--fast skips every NEEDS_IDA file).
NEEDS_IDA = False
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idatui.formats import (  # noqa: E402
    PROCESSORS,
    load_args,
    needs_load_options,
    sniff,
)

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}   {detail}")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:

        def w(name, data):
            p = os.path.join(tmp, name)
            with open(p, "wb") as f:
                f.write(data)
            return p

        # -- formats IDA can load on its own: never interrupt the user -------- #
        for name, head in (
            ("elf", b"\x7fELF\x02\x01\x01"),
            ("pe", b"MZ\x90\x00"),
            ("macho", b"\xcf\xfa\xed\xfe"),
            ("dex", b"dex\n035\x00"),
            ("wasm", b"\x00asm\x01\x00"),
        ):
            p = w(name, head + bytes(60))
            check(
                f"{name} is recognised (no dialog)",
                sniff(p) is not None and not needs_load_options(p),
                f"{sniff(p)}",
            )

        # -- the case this exists for ----------------------------------------- #
        blob = w("fw.bin", bytes(range(256)) * 4)
        check(
            "a headerless blob is not recognised (ask)",
            sniff(blob) is None and needs_load_options(blob),
        )

        # Intel HEX / S-records are text containers IDA does load.
        hexf = w("f.hex", b":10010000214601360121470136007EFE09D2190140\n")
        check("Intel HEX is recognised", sniff(hexf) == "Intel HEX", f"{sniff(hexf)}")
        srec = w(
            "f.s19", b"S00600004844521B\nS1130000285F245F2212226A000424290008237C\n"
        )
        check(
            "Motorola S-records are recognised",
            sniff(srec) == "Motorola S-record",
            f"{sniff(srec)}",
        )

        # A binary that merely STARTS with ':' is not Intel HEX. Text formats are
        # only accepted when the whole head is printable, or half the firmware in
        # the world gets mis-detected on one byte.
        colon = w("colon.bin", b":\x00\xff\xfe\x01\x02" + bytes(58))
        check(
            "a blob starting with ':' is not mistaken for Intel HEX",
            sniff(colon) is None,
            f"{sniff(colon)}",
        )

        check("an empty file is not recognised", sniff(w("empty", b"")) is None)
        check(
            "a missing file never asks (nothing to load)",
            not needs_load_options(os.path.join(tmp, "nope")),
        )
        check("a directory never asks", not needs_load_options(tmp))

    # -- switch construction ------------------------------------------------- #
    # -b is in PARAGRAPHS: 0x8000000 >> 4 == 0x800000. Getting this wrong loads
    # the image 16x off and every address in the database is wrong.
    check(
        "base is converted to paragraphs",
        load_args("arm", 0x8000000) == "-parm -b800000",
        load_args("arm", 0x8000000),
    )
    check("processor alone", load_args("mipsb") == "-pmipsb", load_args("mipsb"))
    check("base alone", load_args("", 0x10000) == "-b1000", load_args("", 0x10000))
    check(
        "base 0 emits no switch (it's the default)",
        load_args("arm", 0) == "-parm",
        load_args("arm", 0),
    )
    check("nothing in, nothing out", load_args() == "")
    check(
        "extra switches pass through",
        load_args("arm", 0, "-T binary") == "-parm -T binary",
    )

    check(
        "the processor list leads with the common targets",
        [n for n, _ in PROCESSORS[:2]] == ["arm", "arm:ARMv7-A"],
        f"{[n for n, _ in PROCESSORS[:3]]}",
    )

    # 32-bit ARM has to be offered SEPARATELY from bare 'arm', which gives a
    # 64-bit database. That isn't cosmetic: Hex-Rays refuses a 32-bit function
    # in a 64-bit database, and Thumb doesn't exist in AArch64 at all, so a
    # firmware image loaded as plain 'arm' can never be decompiled — and the
    # database's bitness cannot be corrected after load.
    check(
        "a 32-bit ARM variant is offered",
        any(n.startswith("arm:ARMv") for n, _ in PROCESSORS),
        f"{[n for n, _ in PROCESSORS if n.startswith('arm')]}",
    )
    check(
        "and the labels say which is 32- vs 64-bit",
        all(
            ("32-bit" in d or "64-bit" in d)
            for n, d in PROCESSORS
            if n == "arm" or n.startswith("arm:")
        ),
        f"{[(n, d) for n, d in PROCESSORS if n.startswith('arm')]}",
    )

    # Every offered name must have been checked against a real IDA, because a
    # wrong one is REJECTED (rc=4) with nothing useful said — handing the user a
    # dead end from inside the dialog meant to rescue them. This list is the
    # output of tools/verify_procs.py; adding a processor without re-running it
    # fails here on purpose.
    VERIFIED = {
        "arm",
        "armb",
        "metapc",
        "mipsl",
        "mipsb",
        "ppc",
        "ppcl",
        "sh4",
        "68k",
        "riscv",
        "tricore",
        "xtensa",
        "avr",
        "z80",
        "tms320c6",
        "m32r",
        "arc",
        "h8300",
        "sparcb",
        "sparcl",
        "s390",
        # variants: tools/verify_procs.py checks these report the base module
        # AND change the database bitness, which is the reason they exist
        "arm:ARMv7-A",
        "arm:ARMv7-M",
        "arm:ARMv6-M",
        "arm:ARMv5TE",
    }
    offered = {n for n, _ in PROCESSORS}
    check(
        "every offered processor name is IDA-verified",
        offered <= VERIFIED,
        f"unverified: {sorted(offered - VERIFIED)}",
    )

    # These are module FILENAMES or common aliases, not -p names. IDA refuses
    # them; they were in the list until a real run said otherwise.
    for wrong in ("h8", "sparc", "arm64", "aarch64", "mips", "m68k"):
        check(f"{wrong!r} is not offered (IDA rejects it)", wrong not in offered)

    # ...but someone WILL type them, so the labels have to carry the alias.
    def finds(q):
        ql = q.lower()
        return [n for n, d in PROCESSORS if ql in n.lower() or ql in d.lower()]

    check(
        "typing 'arm64' still finds ARM", "arm" in finds("arm64"), f"{finds('arm64')}"
    )
    check("typing 'aarch64' still finds ARM", "arm" in finds("aarch64"))
    check("typing 'm68k' still finds 68k", "68k" in finds("m68k"), f"{finds('m68k')}")
    check(
        "typing 'mips' finds both endiannesses",
        set(finds("mips")) == {"mipsl", "mipsb"},
        f"{finds('mips')}",
    )
    check(
        "every processor entry has a human label", all(n and d for n, d in PROCESSORS)
    )
    check(
        "endianness is spelled out where it matters",
        all(
            any(w in d.lower() for w in ("endian",))
            for n, d in PROCESSORS
            if n in ("arm", "armb", "mipsb", "mipsl")
        ),
    )

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
