"""Generate the README illustrations.

Usage: python tools/branding/readme_art.py docs/assets

Writes:
  readme-hero-light.svg / readme-hero-dark.svg  maximum certificate lifetime by date
  readme-flow-light.svg / readme-flow-dark.svg  sources, correlation, classification, report

Palette matches tools/branding/logo_gen.py: ink/paper swap, constant accent.
"""
import sys
out=sys.argv[1]
themes={
 "light":dict(bg="#FFFFFF",fg="#1B2433",muted="#59636E",grid="#EAEEF2",navy="#1B2433",teal="#0FA3B1",cyan="#5CC8D2",warn="#B35900",card="#F6F8FA",stroke="#D0D7DE"),
 "dark": dict(bg="#0D1117",fg="#E6EDF3",muted="#9198A1",grid="#262C36",navy="#F6F3EC",teal="#0FA3B1",cyan="#5CC8D2",warn="#F0A83A",card="#161B22",stroke="#3D444D"),
}
FONT="font-family=\"-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif\""
def hero(t):
    rows=[("until 2026-03-14",398,"1","",t["navy"]),("from 2026-03-15",200,"2","in force",t["navy"]),
          ("from 2027-03-15",100,"4","next step",t["teal"]),("from 2029-03-15",47,"8","DCV reuse: 10 days",t["cyan"])]
    W,H=880,320; x0,bw=190,420; s=[f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-label="Maximum public TLS certificate lifetime: 398, 200, 100, then 47 days">',
      f'<rect width="{W}" height="{H}" rx="12" fill="{t["bg"]}" stroke="{t["stroke"]}"/>',
      f'<text x="28" y="40" {FONT} font-size="17" font-weight="600" fill="{t["fg"]}">Maximum lifetime of a public TLS certificate</text>',
      f'<text x="{W-28}" y="40" {FONT} font-size="13" fill="{t["muted"]}" text-anchor="end">CA/Browser Forum ballot SC-081v3</text>',
      f'<text x="{x0+bw+24}" y="72" {FONT} font-size="12" fill="{t["muted"]}">renewals per year</text>']
    for i,(lab,d,ren,note,col) in enumerate(rows):
        y=92+i*48; w=bw*d/398
        s.append(f'<text x="28" y="{y+19}" {FONT} font-size="14" fill="{t["fg"]}">{lab}</text>')
        s.append(f'<rect x="{x0}" y="{y}" width="{bw}" height="28" rx="6" fill="{t["grid"]}"/>')
        s.append(f'<rect x="{x0}" y="{y}" width="{w:.1f}" height="28" rx="6" fill="{col}"/>')
        inside = w>90
        tx = x0+10 if inside else x0+w+8
        tc = t["bg"] if inside else t["fg"]
        s.append(f'<text x="{tx:.1f}" y="{y+19}" {FONT} font-size="14" font-weight="600" fill="{tc}">{d} days</text>')
        s.append(f'<text x="{x0+bw+24}" y="{y+19}" {FONT} font-size="16" font-weight="700" fill="{col}">≈ {ren}</text>')
        if note: s.append(f'<text x="{x0+bw+70}" y="{y+19}" {FONT} font-size="12" fill="{t["warn"] if note=="next step" else t["muted"]}">{note}</text>')
    s.append(f'<text x="28" y="{H-20}" {FONT} font-size="13" fill="{t["muted"]}">A manual renewal that happens once a year today becomes a job you do every quarter, then every six weeks.</text>')
    s.append('</svg>'); return "\n".join(s)
def flow(t):
    W,H=880,300; s=[f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-label="Sources are correlated by fingerprint, renewal is classified, and a report is produced">',
      f'<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="{t["muted"]}"/></marker></defs>',
      f'<rect width="{W}" height="{H}" rx="12" fill="{t["bg"]}" stroke="{t["stroke"]}"/>']
    srcs=[("Certificate Transparency","what was issued",False),("TLS handshake (SNI)","what is served",False),("Kubernetes + cert-manager","what is managed",False),("Azure Key Vault","planned",True)]
    for i,(a,b,planned) in enumerate(srcs):
        y=28+i*62
        dash=' stroke-dasharray="5 4"' if planned else ''
        s.append(f'<rect x="24" y="{y}" width="230" height="50" rx="8" fill="{t["card"]}" stroke="{t["stroke"]}"{dash}/>')
        s.append(f'<text x="38" y="{y+22}" {FONT} font-size="14" font-weight="600" fill="{t["fg"] if not planned else t["muted"]}">{a}</text>')
        s.append(f'<text x="38" y="{y+40}" {FONT} font-size="12" fill="{t["muted"]}">{b}</text>')
        s.append(f'<path d="M254,{y+25} C300,{y+25} 300,150 336,150" fill="none" stroke="{t["muted"]}" stroke-width="1.5" marker-end="url(#a)"{dash}/>')
    boxes=[(340,"Correlate","one certificate, every","place it appears",t["navy"],False),(520,"Classify renewal","automatic · manual","· unknown",t["teal"],True)]
    for x,a,b,c,col,planned in boxes:
        dash=' stroke-dasharray="5 4"' if planned else ''
        s.append(f'<rect x="{x}" y="112" width="150" height="76" rx="10" fill="{t["card"]}" stroke="{col}" stroke-width="2"{dash}/>')
        s.append(f'<text x="{x+75}" y="138" {FONT} font-size="14" font-weight="700" fill="{col}" text-anchor="middle">{a}</text>')
        s.append(f'<text x="{x+75}" y="158" {FONT} font-size="12" fill="{t["muted"]}" text-anchor="middle">{b}</text>')
        s.append(f'<text x="{x+75}" y="174" {FONT} font-size="12" fill="{t["muted"]}" text-anchor="middle">{c}</text>')
    s.append(f'<path d="M490,150 L516,150" stroke="{t["muted"]}" stroke-width="1.5" marker-end="url(#a)"/>')
    s.append(f'<path d="M670,150 L696,150" stroke="{t["muted"]}" stroke-width="1.5" marker-end="url(#a)"/>')
    s.append(f'<rect x="700" y="96" width="156" height="108" rx="10" fill="{t["card"]}" stroke="{t["stroke"]}"/>')
    for j,(a) in enumerate(["Report","table · JSON · CSV","owner, location","ct_only · live_only","exit code for CI"]):
        s.append(f'<text x="778" y="{122+j*19}" {FONT} font-size="{14 if j==0 else 12}" font-weight="{700 if j==0 else 400}" fill="{t["fg"] if j==0 else t["muted"]}" text-anchor="middle">{a}</text>')
    s.append(f'<text x="24" y="{H-16}" {FONT} font-size="12" fill="{t["muted"]}">Dashed: planned. Read-only everywhere: list and get, never write.</text>')
    s.append('</svg>'); return "\n".join(s)
for name,t in themes.items():
    open(f"{out}/readme-hero-{name}.svg","w",encoding="utf-8",newline="\n").write(hero(t))
    open(f"{out}/readme-flow-{name}.svg","w",encoding="utf-8",newline="\n").write(flow(t))
print("ok")
