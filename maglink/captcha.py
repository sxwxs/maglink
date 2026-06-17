"""Dependency-free SVG captcha.

Avoids Pillow/external image libs: returns an inline SVG data URI with the code
drawn as distorted text. Not a strong bot defense on its own — it exists to slow
down trivial automated abuse and pairs with rate limiting in the core.
"""

from __future__ import annotations

import html
import secrets

# Avoid visually ambiguous characters (0/O, 1/I/L).
_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


class Captcha:
    def __init__(self, length: int = 5) -> None:
        self.length = length

    def generate(self) -> tuple[str, str]:
        """Return ``(code, svg_data_uri)``. Store the code server-side; show the SVG."""
        code = "".join(secrets.choice(_ALPHABET) for _ in range(self.length))
        return code, self._svg(code)

    @staticmethod
    def check(expected: str, given: str) -> bool:
        if not expected or not given:
            return False
        # Constant-time-ish, case-insensitive compare.
        return secrets.compare_digest(expected.upper(), given.strip().upper())

    def _svg(self, code: str) -> str:
        w, h = 36 * len(code) + 20, 60
        parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
            f'viewBox="0 0 {w} {h}">',
            f'<rect width="{w}" height="{h}" fill="#f2f3f5"/>',
        ]
        # noise lines (deterministic-looking but seeded by fresh randomness)
        for _ in range(5):
            x1, y1 = secrets.randbelow(w), secrets.randbelow(h)
            x2, y2 = secrets.randbelow(w), secrets.randbelow(h)
            parts.append(
                f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
                f'stroke="#c9ced6" stroke-width="1"/>'
            )
        for i, ch in enumerate(code):
            x = 18 + i * 36
            y = 38 + (secrets.randbelow(10) - 5)
            rot = secrets.randbelow(31) - 15
            parts.append(
                f'<text x="{x}" y="{y}" font-family="monospace" font-size="34" '
                f'font-weight="bold" fill="#33373d" '
                f'transform="rotate({rot} {x} {y})">{html.escape(ch)}</text>'
            )
        parts.append("</svg>")
        svg = "".join(parts)
        # Inline SVG as a data URI so the frontend can drop it into <img src>.
        import base64

        b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
        return f"data:image/svg+xml;base64,{b64}"
