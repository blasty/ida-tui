#!/usr/bin/env python3
"""Format sniffing + load-switch construction (pure stdlib, no IDA)."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idatui.formats import (PROCESSORS, load_args,  # noqa: E402
                            needs_load_options, sniff)

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
        for name, head in (("elf", b"\x7fELF\x02\x01\x01"), ("pe", b"MZ\x90\x00"),
                           ("macho", b"\xcf\xfa\xed\xfe"), ("dex", b"dex\n035\x00"),
                           ("wasm", b"\x00asm\x01\x00")):
            p = w(name, head + bytes(60))
            check(f"{name} is recognised (no dialog)",
                  sniff(p) is not None and not needs_load_options(p), f"{sniff(p)}")

        # -- the case this exists for ----------------------------------------- #
        blob = w("fw.bin", bytes(range(256)) * 4)
        check("a headerless blob is not recognised (ask)",
              sniff(blob) is None and needs_load_options(blob))

        # Intel HEX / S-records are text containers IDA does load.
        hexf = w("f.hex", b":10010000214601360121470136007EFE09D2190140\n")
        check("Intel HEX is recognised", sniff(hexf) == "Intel HEX", f"{sniff(hexf)}")
        srec = w("f.s19", b"S00600004844521B\nS1130000285F245F2212226A000424290008237C\n")
        check("Motorola S-records are recognised",
              sniff(srec) == "Motorola S-record", f"{sniff(srec)}")

        # A binary that merely STARTS with ':' is not Intel HEX. Text formats are
        # only accepted when the whole head is printable, or half the firmware in
        # the world gets mis-detected on one byte.
        colon = w("colon.bin", b":\x00\xff\xfe\x01\x02" + bytes(58))
        check("a blob starting with ':' is not mistaken for Intel HEX",
              sniff(colon) is None, f"{sniff(colon)}")

        check("an empty file is not recognised", sniff(w("empty", b"")) is None)
        check("a missing file never asks (nothing to load)",
              not needs_load_options(os.path.join(tmp, "nope")))
        check("a directory never asks", not needs_load_options(tmp))

    # -- switch construction ------------------------------------------------- #
    # -b is in PARAGRAPHS: 0x8000000 >> 4 == 0x800000. Getting this wrong loads
    # the image 16x off and every address in the database is wrong.
    check("base is converted to paragraphs",
          load_args("arm", 0x8000000) == "-parm -b800000",
          load_args("arm", 0x8000000))
    check("processor alone", load_args("mipsb") == "-pmipsb", load_args("mipsb"))
    check("base alone", load_args("", 0x10000) == "-b1000", load_args("", 0x10000))
    check("base 0 emits no switch (it's the default)",
          load_args("arm", 0) == "-parm", load_args("arm", 0))
    check("nothing in, nothing out", load_args() == "")
    check("extra switches pass through",
          load_args("arm", 0, "-T binary") == "-parm -T binary")

    check("the processor list leads with the common targets",
          [n for n, _ in PROCESSORS[:3]] == ["arm", "armb", "metapc"],
          f"{[n for n, _ in PROCESSORS[:3]]}")
    check("every processor entry has a human label",
          all(n and d for n, d in PROCESSORS))
    check("endianness is spelled out where it matters",
          all(any(w in d.lower() for w in ("endian",))
              for n, d in PROCESSORS if n in ("arm", "armb", "mipsb", "mipsl")))

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
