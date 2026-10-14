"""Generate the scadenza logo: a certificate shield with a countdown clock.

Usage: python tools/branding/logo_gen.py docs/assets [preview.html]
The optional preview page must not be committed.

Same system as trasloco's logo: flat vector marks, an ink/paper swap for dark
mode, and one accent colour that stays constant in both themes.
"""
import base64, math, os, sys

OUT = sys.argv[1]
INK, PAPER, ACCENT = "#1B2433", "#F6F3EC", "#0FA3B1"
GAP = 6.0  # clearance cut around the clock, like the tape gap in trasloco

# Geometry of the mark in a 128x128 box. Shield centre line at SX.
CLOCK_C, CLOCK_R, RING_W = (88.0, 86.0), 24.0, 7.0


def shield_path(sx):
    top, shoulder_y, side_bottom, tip = 12.0, 24.0, 66.0, 118.0
    half = 36.0
    return (
        f"M{sx:.2f},{top:.2f} "
        f"C{sx - 12:.2f},{top + 8:.2f} {sx - 24:.2f},{shoulder_y - 2:.2f} {sx - half:.2f},{shoulder_y:.2f} "
        f"L{sx - half:.2f},{side_bottom:.2f} "
        f"C{sx - half:.2f},{side_bottom + 26:.2f} {sx - 14:.2f},{tip - 10:.2f} {sx:.2f},{tip:.2f} "
        f"C{sx + 14:.2f},{tip - 10:.2f} {sx + half:.2f},{side_bottom + 26:.2f} {sx + half:.2f},{side_bottom:.2f} "
        f"L{sx + half:.2f},{shoulder_y:.2f} "
        f"C{sx + 24:.2f},{shoulder_y - 2:.2f} {sx + 12:.2f},{top + 8:.2f} {sx:.2f},{top:.2f} Z"
    )


def mark(ox, body, uid, clock=True, detail=True):
    """ox shifts the whole mark horizontally; body is the ink (or paper) colour."""
    sx = 46.0 + ox
    cx, cy = CLOCK_C[0] + ox, CLOCK_C[1]
    cut = CLOCK_R + RING_W / 2 + GAP
    mask = (
        f'<mask id="m{uid}" maskUnits="userSpaceOnUse"><rect x="-20" y="-20" width="480" height="200" fill="#fff"/>'
        + (f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{cut:.2f}" fill="#000"/>' if clock else "")
        + "</mask>"
    )
    shield = (
        f'<g mask="url(#m{uid})">'
        f'<path d="{shield_path(sx)}" fill="none" stroke="{body}" stroke-width="7" stroke-linejoin="round"/>'
        + (
            f'<line x1="{sx - 20:.2f}" y1="40" x2="{sx + 18:.2f}" y2="40" stroke="{body}" stroke-width="6" stroke-linecap="round" opacity="0.55"/>'
            f'<line x1="{sx - 20:.2f}" y1="54" x2="{sx + 8:.2f}" y2="54" stroke="{body}" stroke-width="6" stroke-linecap="round" opacity="0.55"/>'
            if detail else ""
        )
        # seal with ribbon
        +
        f'<path d="M{sx - 20:.2f},80 L{sx - 20:.2f},98 L{sx - 13:.2f},93 L{sx - 6:.2f},98 L{sx - 6:.2f},80 Z" fill="{body}"/>'
        f'<circle cx="{sx - 13:.2f}" cy="76" r="10" fill="{ACCENT}"/>'
        "</g>"
    )
    if not clock:
        return f"<defs>{mask}</defs>{shield}"
    ring = f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{CLOCK_R:.2f}" fill="none" stroke="{ACCENT}" stroke-width="{RING_W}"/>'
    hands = (
        f'<polyline points="{cx:.2f},{cy - 14:.2f} {cx:.2f},{cy:.2f} {cx + 10:.2f},{cy + 8:.2f}" fill="none" '
        f'stroke="{body}" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>'
        f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="3.6" fill="{body}"/>'
    )
    # countdown ticks on the upper-right of the ring, shrinking clockwise
    ticks = []
    for i, ang in enumerate([-84, -62, -40, -18, 4] if detail else []):
        a = math.radians(ang)
        r1, r2 = CLOCK_R + 9, CLOCK_R + 9 + (8 - i * 1.2)
        x1, y1 = cx + r1 * math.cos(a), cy + r1 * math.sin(a)
        x2, y2 = cx + r2 * math.cos(a), cy + r2 * math.sin(a)
        ticks.append(
            f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" stroke="{ACCENT}" stroke-width="4.5" '
            f'stroke-linecap="round" opacity="{1 - i * 0.15:.2f}"/>'
        )
    return f"<defs>{mask}</defs>{shield}{ring}{''.join(ticks)}{hands}"


def svg(w, h, inner):
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" role="img" aria-label="scadenza"><title>scadenza</title>{inner}</svg>\n'


WORD = (
    "font-family=\"'JetBrains Mono','SFMono-Regular',Menlo,Consolas,'Liberation Mono',monospace\" "
    'font-size="54" font-weight="700" letter-spacing="-1.5"'
)


def word(body):
    return f'<text x="150" y="86" fill="{body}" {WORD}>sca<tspan fill="{ACCENT}">denza</tspan></text>'


files = {
    "scadenza-icon.svg": svg(128, 128, mark(-6, INK, "il")),
    "scadenza-icon-dark.svg": svg(128, 128, mark(-6, PAPER, "id")),
    "scadenza-favicon.svg": svg(128, 128, mark(-6, INK, "fl", detail=False)),
    "scadenza-logo.svg": svg(440, 128, mark(0, INK, "ll") + word(INK)),
    "scadenza-logo-dark.svg": svg(440, 128, mark(0, PAPER, "ld") + word(PAPER)),
}
os.makedirs(OUT, exist_ok=True)
for n, c in files.items():
    with open(os.path.join(OUT, n), "w", encoding="utf-8", newline="\n") as f:
        f.write(c)


def img(c, h):
    return f'<img style="height:{h}px" src="data:image/svg+xml;base64,{base64.b64encode(c.encode()).decode()}">'


def panel(bg, items):
    return f'<div style="background:{bg};padding:22px;border-radius:12px;display:flex;align-items:flex-end;gap:22px;flex-wrap:wrap">{items}</div>'


i_l, i_d, fav = files["scadenza-icon.svg"], files["scadenza-icon-dark.svg"], files["scadenza-favicon.svg"]
html = (
    "<!doctype html><meta charset=utf-8><title>scadenza concept</title>"
    '<body style="margin:0;padding:22px;background:#e6e3dc;display:grid;gap:14px">'
    + panel("#fff", img(i_l, 160) + img(i_l, 64) + img(i_l, 32) + img(fav, 32) + img(fav, 16))
    + panel(INK, img(i_d, 160) + img(i_d, 64) + img(i_d, 32))
    + panel("#fff", img(files["scadenza-logo.svg"], 96) + img(files["scadenza-logo.svg"], 40))
    + panel("#0D1117", img(files["scadenza-logo-dark.svg"], 96) + img(files["scadenza-logo-dark.svg"], 40))
    + "</body>"
)
if len(sys.argv) > 2:
    open(sys.argv[2], "w", encoding="utf-8").write(html)
print("ok")
