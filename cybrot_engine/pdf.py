"""A small PDF writer for CYBROT reports, laid out to match the CYBROT Word template.

Standard Helvetica and Courier fonts only, so no font files are embedded. Each page has the template header
(icon, wordmark, tagline and colour bar) and the template footer (contact line and page number). There is no
watermark. The icon PNG is embedded as-is: PDF readers undo its row filters themselves (Predictor 15).
"""
import struct
import textwrap
import zlib

PAGE_W = 595.0  # A4 in points
PAGE_H = 842.0
MARGIN = 50.0  # the template's 1000-twip side margins
USABLE_W = PAGE_W - 2 * MARGIN
BOTTOM = 70.0  # body text stops above the footer
TOP = PAGE_H - 125.0  # body text starts below the header

FONTS = {"regular": ("F1", "Helvetica"), "bold": ("F2", "Helvetica-Bold"), "mono": ("F3", "Courier")}
CHAR_EM = {"regular": 0.55, "bold": 0.6, "mono": 0.6}  # average character width, in em, for wrapping

# Colours from the template (hex in the Word file, converted to 0-1 values for PDF).
INK = (0x0B / 255, 0x15 / 255, 0x20 / 255)
GREY = (0x6B / 255, 0x7B / 255, 0x85 / 255)
RULE = (0xE3 / 255, 0xE8 / 255, 0xEB / 255)
GREEN = (0x2F / 255, 0xE3 / 255, 0x8A / 255)
BLUE = (0x3B / 255, 0x9E / 255, 0xFF / 255)
BLACK = (0, 0, 0)

# Header geometry, from the template: icon 45 x 67.5 pt at the top-left, text in a column to its right.
ICON_W = 45.0
ICON_H = 67.5
ICON_X = MARGIN
ICON_Y = PAGE_H - 25.0 - ICON_H
TEXT_X = MARGIN + 75.0
BAR_Y = ICON_Y - 12.0
CONTACT_LINE = "support@cybrot.com   |   www.cybrot.com   |   UDYAM-MP-10-0181215"


def _literal(text):
    """A PDF string in WinAnsi encoding, with the characters PDF needs escaped."""
    raw = str(text).encode("cp1252", errors="replace")
    for char, escaped in ((b"\\", b"\\\\"), (b"(", b"\\("), (b")", b"\\)")):
        raw = raw.replace(char, escaped)
    return b"(" + raw + b")"


def _rgb(color):
    return "{:.3f} {:.3f} {:.3f}".format(*color)


def _wrap(text, font, size, width):
    chars = max(6, int(width / (size * CHAR_EM[font])))
    cleaned = " ".join(str(text).split())
    if not cleaned:
        return [""]
    return textwrap.wrap(cleaned, width=chars, break_long_words=True, break_on_hyphens=False)


def icon_png_info(data):
    """Returns (width, height, idat) for an 8-bit RGB, non-interlaced PNG. The IDAT bytes go into the PDF as-is."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG file")
    pos, idat, header = 8, [], None
    while pos < len(data):
        length, = struct.unpack(">I", data[pos:pos + 4])
        kind = data[pos + 4:pos + 8]
        chunk = data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if kind == b"IHDR":
            header = struct.unpack(">IIBBBBB", chunk)
        elif kind == b"IDAT":
            idat.append(chunk)
        elif kind == b"IEND":
            break
    if header is None:
        raise ValueError("PNG has no header")
    width, height, depth, colour, _, _, interlace = header
    if depth != 8 or colour != 2 or interlace:
        raise ValueError("only 8-bit RGB, non-interlaced PNG is supported")
    return width, height, b"".join(idat)


class PdfDocument:
    def __init__(self):
        self._pages = []
        self._new_page()

    # ---- layout ----

    def _new_page(self):
        self._ops = []
        self._pages.append(self._ops)
        self._y = TOP
        self._header()

    def _header(self):
        """The template header: icon, wordmark, two tagline lines and the green and blue bar."""
        self._ops.append(f"q {ICON_W:.2f} 0 0 {ICON_H:.2f} {ICON_X:.2f} {ICON_Y:.2f} cm /IM1 Do Q".encode("ascii"))
        self._show("CYBROT", "bold", 20, TEXT_X, PAGE_H - 54.0, color=INK, spacing=1.5)
        self._show("TECHNOLOGIES", "bold", 20, TEXT_X + 112.0, PAGE_H - 54.0, color=GREY, spacing=1.5)
        self._show("VAPT & PENETRATION TESTING   ·   SECURITY AUDITS   ·   VULNERABILITY SCANNING",
                   "mono", 6.5, TEXT_X, PAGE_H - 68.0, color=GREY, spacing=0.2)
        self._show("CLOUD SECURITY (CSPM) · DPDP & CERT-IN COMPLIANCE   ·   SECURE CODE REVIEW",
                   "mono", 6.5, TEXT_X, PAGE_H - 78.0, color=GREY, spacing=0.2)
        half = USABLE_W / 2
        self._ops.append(f"{_rgb(GREEN)} rg {MARGIN:.1f} {BAR_Y:.1f} {half:.1f} 2 re f".encode("ascii"))
        self._ops.append(f"{_rgb(BLUE)} rg {MARGIN + half:.1f} {BAR_Y:.1f} {half:.1f} 2 re f".encode("ascii"))

    def _show(self, text, font, size, x, y, color=BLACK, spacing=0.0):
        name = FONTS[font][0]
        tc = f"{spacing:.2f} Tc " if spacing else ""
        head = f"BT /{name} {size} Tf {_rgb(color)} rg {tc}{x:.1f} {y:.1f} Td ".encode("ascii")
        self._ops.append(head + _literal(text) + b" Tj ET")

    def text(self, text, font="regular", size=10, gap_after=4):
        leading = size * 1.35
        for line in _wrap(text, font, size, USABLE_W):
            if self._y - leading < BOTTOM:
                self._new_page()
            self._y -= leading
            self._show(line, font, size, MARGIN, self._y)
        self._y -= gap_after

    def heading(self, text):
        if self._y - 44 < BOTTOM:
            self._new_page()
        self._y -= 18
        self._show(text, "bold", 13, MARGIN, self._y, color=INK)
        self._y -= 7
        self._ops.append(
            f"{_rgb(RULE)} RG 0.8 w {MARGIN:.1f} {self._y:.1f} m {PAGE_W - MARGIN:.1f} {self._y:.1f} l S".encode("ascii")
        )
        self._y -= 9

    def table(self, headers, rows, ratios=None):
        columns = len(headers) if headers else len(rows[0]) if rows else 2
        ratios = ratios or [1] * columns
        scale = USABLE_W / float(sum(ratios))
        widths = [r * scale for r in ratios]
        if not rows:
            rows = [["No data returned."] + [""] * (columns - 1)]

        def emit(cells, header):
            font = "bold" if header else "regular"
            lines = [_wrap(cell, font, 8, width - 6) for cell, width in zip(cells, widths)]
            height = max(len(col) for col in lines) * 10 + 6
            if self._y - height < BOTTOM:
                self._new_page()
                if headers and not header:
                    emit(headers, True)  # repeat the header on each new page
            top = self._y
            if header:
                self._ops.append(f"{_rgb((0.945, 0.953, 0.961))} rg {MARGIN:.1f} {top - height:.1f} "
                                 f"{USABLE_W:.1f} {height:.1f} re f".encode("ascii"))
            x = MARGIN
            for col_lines, width in zip(lines, widths):
                for index, line in enumerate(col_lines):
                    self._show(line, font, 8, x + 3, top - 10 - index * 10, color=INK if header else BLACK)
                x += width
            self._y = top - height
            self._ops.append(
                f"{_rgb(RULE)} RG 0.4 w {MARGIN:.1f} {self._y:.1f} m {PAGE_W - MARGIN:.1f} {self._y:.1f} l S".encode("ascii")
            )

        if headers:
            emit(headers, True)
        for row in rows:
            emit(list(row), False)
        self._y -= 8

    # ---- output ----

    def _footer(self, number, count, meta):
        ops = [f"{_rgb(RULE)} RG 0.5 w {MARGIN:.1f} 52.0 m {PAGE_W - MARGIN:.1f} 52.0 l S".encode("ascii")]
        page_text = f"Page {number} of {count}"
        right = PAGE_W - MARGIN - len(page_text) * 0.5 * 7.5
        out = []
        for text, x, y, font, size in (
            (CONTACT_LINE, MARGIN, 40.0, "regular", 7.5),
            (page_text, right, 40.0, "regular", 7.5),
            (meta, MARGIN, 29.0, "mono", 6.5),
        ):
            name = FONTS[font][0]
            out.append(f"BT /{name} {size} Tf {_rgb(GREY)} rg {x:.1f} {y:.1f} Td ".encode("ascii")
                       + _literal(text) + b" Tj ET")
        return ops + out

    def to_bytes(self, title, footer):
        """Builds the PDF. footer is the small grey line at the bottom of each page (scan details)."""
        count = len(self._pages)
        meta = " ".join(str(footer).split())
        icon_width, icon_height, icon_idat = self._icon()
        image_number = 7 + 2 * count  # the icon comes after all page objects

        streams = []
        for number, ops in enumerate(self._pages, start=1):
            foot = self._footer(number, count, meta)
            streams.append(b"\n".join(ops + foot))

        def font_object(base):
            return f"<< /Type /Font /Subtype /Type1 /BaseFont /{base} /Encoding /WinAnsiEncoding >>".encode("ascii")

        page_numbers = [7 + 2 * i for i in range(count)]
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [" + " ".join(f"{n} 0 R" for n in page_numbers).encode("ascii")
            + f"] /Count {count} >>".encode("ascii"),
            font_object("Helvetica"),
            font_object("Helvetica-Bold"),
            font_object("Courier"),
            b"<< /Title " + _literal(title) + b" /Producer (CYBROT engine) /Creator (CYBROT engine) >>",
        ]
        for index, stream in enumerate(streams):
            objects.append(
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W:g} {PAGE_H:g}] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> "
                f"/XObject << /IM1 {image_number} 0 R >> >> "
                f"/Contents {8 + 2 * index} 0 R >>".encode("ascii")
            )
            objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream")
        objects.append(
            f"<< /Type /XObject /Subtype /Image /Width {icon_width} /Height {icon_height} "
            f"/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode "
            f"/DecodeParms << /Predictor 15 /Colors 3 /BitsPerComponent 8 /Columns {icon_width} >> "
            f"/Length {len(icon_idat)} >>\nstream\n".encode("ascii") + icon_idat + b"\nendstream"
        )

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for number, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{number} 0 obj\n".encode("ascii") + body + b"\nendobj\n"
        xref_at = len(out)
        out += f"xref\n0 {len(objects) + 1}\n".encode("ascii") + b"0000000000 65535 f \n"
        for offset in offsets:
            out += f"{offset:010d} 00000 n \n".encode("ascii")  # every xref entry is exactly 20 bytes
        out += (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info 6 0 R >>\n"
            f"startxref\n{xref_at}\n%%EOF\n"
        ).encode("ascii")
        return bytes(out)

    def _icon(self):
        from . import brand
        return icon_png_info(brand.icon_png_bytes())
