"""Informe HTML autocontenido del caso (WinHound, Windows).

Documento HTML estático único (CSS embebido, sin assets externos) a partir de lo
que ya calcula la app: resumen, detecciones Sigma (colapsables, con los matches),
pestañas LOL (findings + gráfica de top indicador), top IPs con GeoIP y marcas.
Las secciones usan <details> nativo: todo plegable y nada abrumador de primeras.
"""
from __future__ import annotations

import html
import time
from typing import Any, Optional

_SEV = {"critical": "#f85149", "high": "#db6d28", "medium": "#e3b341",
        "low": "#3fb950", "informational": "#58a6ff"}


def _e(v: Any) -> str:
    if v is None:
        return "&empty;"
    return html.escape(str(v))


def _tile(value: Any, label: str) -> str:
    return f'<div class="tile"><div class="v">{_e(value)}</div><div class="l">{_e(label)}</div></div>'


def _findings_html(findings: list) -> str:
    body = []
    for f in findings:
        lvl = (f.get("level") or "info")
        col = _SEV.get(lvl, "#58a6ff")
        cols = f.get("columns", [])
        rows = []
        for hit in f.get("hits", []):
            tds = "".join(f"<td>{_e(c)}</td>" for c in hit)
            rows.append(f"<tr>{tds}</tr>")
        more = ""
        if f.get("count", 0) > len(f.get("hits", [])):
            more = (f'<tr><td colspan="{len(cols)}" class="muted">… '
                    f'{f["count"] - len(f["hits"])} more</td></tr>')
        thead = "".join(f"<th>{_e(c)}</th>" for c in cols)
        tags = " ".join(_e(t) for t in f.get("tags", []))
        body.append(
            f'<details class="finding"><summary>'
            f'<span class="sev" style="background:{col}">{_e(lvl.upper())}</span> '
            f'{_e(f.get("title"))} <span class="muted">· {_e(f.get("logsource"))} '
            f'· ×{f.get("count", 0)} {("· " + tags) if tags else ""}</span></summary>'
            f'<div class="tblwrap"><table><thead><tr>{thead}</tr></thead>'
            f'<tbody>{"".join(rows)}{more}</tbody></table></div></details>')
    return "".join(body)


def _bars(chart: list, label: str) -> str:
    if not chart:
        return ""
    mx = max((c["n"] for c in chart), default=1) or 1
    rows = []
    for c in chart:
        pct = max(2, round(c["n"] / mx * 100))
        rows.append(
            f'<div class="bar"><span class="bk">{_e(c["k"])}</span>'
            f'<span class="bt"><span class="bf" style="width:{pct}%"></span></span>'
            f'<span class="bn">{c["n"]}</span></div>')
    return (f'<div class="subh">Top {_e(label)} (events that hit)</div>'
            f'{"".join(rows)}')


def _sigma_section(sigma: Optional[dict]) -> str:
    if sigma is None:
        return ('<details><summary>Sigma detections <span class="muted">'
                '(rules not loaded)</span></summary><p class="muted">Load Sigma '
                'rules and run them to include detections here.</p></details>')
    findings = sigma.get("findings", [])
    head = (f'Sigma detections <span class="pill">{len(findings)} findings · '
            f'{sigma.get("total_hits", 0)} hits · {sigma.get("applied", 0)} rules run</span>')
    if not findings:
        return f'<details open><summary>{head}</summary><p class="muted">No matches.</p></details>'
    return f'<details open><summary>{head}</summary>{_findings_html(findings)}</details>'


def _lol_section(lol: dict, labels: dict) -> str:
    if not lol:
        return ""
    out = []
    for cat, res in lol.items():
        findings = res.get("findings", [])
        name = labels.get(cat, cat)
        head = (f'{_e(name)} <span class="pill">{len(findings)} findings · '
                f'{res.get("total_hits", 0)} hits</span>')
        chart = _bars(res.get("chart", []), res.get("indicator", "indicator"))
        inner = chart + (_findings_html(findings) if findings
                         else '<p class="muted">No matches.</p>')
        out.append(f'<details><summary>{head}</summary>{inner}</details>')
    return "".join(out)


def _ip_section(title: str, ips: list) -> str:
    if not ips:
        return ""
    rows = []
    for x in ips:
        if x.get("private") is True:
            loc = '<span class="tag int">internal</span>'
        elif x.get("private") is False:
            geo = " · ".join(str(v) for v in
                             [x.get("country"), f"AS{x['asn']}" if x.get("asn") else None,
                              x.get("org")] if v)
            loc = f'<span class="tag ext">external</span> {_e(geo)}'
        else:
            loc = ""
        rows.append(f'<tr><td class="mono">{_e(x.get("k"))}</td>'
                    f'<td class="mono">{x.get("n")}</td><td>{loc}</td></tr>')
    return (f'<details><summary>{_e(title)}</summary><div class="tblwrap">'
            f'<table><thead><tr><th>IP</th><th>events</th><th>location</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div></details>')


def _marks_section(marks: list) -> str:
    if not marks:
        return ('<details><summary>Triage marks</summary>'
                '<p class="muted">No marks.</p></details>')
    from collections import Counter
    lbl = {"pendiente": "pending", "descartado": "dismissed", "TP": "TP", "FP": "FP"}
    c = Counter(lbl.get(m["estado"], m["estado"]) for m in marks)
    counts = " · ".join(f"{k}: {v}" for k, v in c.items())
    rows = []
    for m in marks:
        meta = " · ".join(str(v) for v in
                          [f"#{m['seq']}" if m.get("seq") is not None else None,
                           m.get("ts"), m.get("source"), m.get("user")] if v)
        note = f'<div class="note">{_e(m.get("nota"))}</div>' if m.get("nota") else ""
        rows.append(f'<div class="mk"><span class="badge badge-{_e(m["estado"])}">'
                    f'{_e(lbl.get(m["estado"], m["estado"]))}</span><div><div class="mono">'
                    f'{_e(m.get("detalle") or "(no event)")}</div>'
                    f'<div class="muted small">{_e(meta)}</div>{note}</div></div>')
    return (f'<details><summary>Triage marks <span class="pill">{_e(counts)}'
            f'</span></summary>{"".join(rows)}</details>')


_CSS = """
:root{--bg:#132743;--panel:#1b3357;--panel2:#23416b;--border:#345681;--fg:#eaf1fb;
--muted:#a3b6d4;--accent:#5fa3ff;--ink:#07192f;--mono:ui-monospace,Menlo,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 system-ui,sans-serif;padding:0 0 40px}
header{padding:22px 28px;border-bottom:1px solid var(--border);background:linear-gradient(180deg,#1d3860,#132743)}
h1{margin:0;font-size:20px}
.sub{color:var(--muted);font-size:12px;margin-top:4px;font-family:var(--mono)}
main{max-width:1100px;margin:0 auto;padding:24px}
.tiles{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:22px}
.tile{flex:1;min-width:130px;background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:12px 14px}
.tile .v{font-size:22px;font-weight:700;color:var(--accent);font-family:var(--mono)}
.tile .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:3px}
details{background:var(--panel);border:1px solid var(--border);border-radius:12px;margin:12px 0;padding:4px 14px}
details>summary{cursor:pointer;padding:10px 4px;font-size:14px;font-weight:600;list-style:none}
details>summary::-webkit-details-marker{display:none}
details>summary::before{content:"\\25B6";color:var(--accent);font-size:10px;margin-right:9px;display:inline-block;transition:transform .12s}
details[open]>summary::before{transform:rotate(90deg)}
details.finding{background:var(--bg);margin:8px 0}
.sev{font-family:var(--mono);font-size:10px;font-weight:700;color:var(--ink);padding:2px 7px;border-radius:4px}
.pill{font-weight:400;font-size:12px;color:var(--muted);font-family:var(--mono)}
.muted{color:var(--muted)}.small{font-size:11px}
.mono{font-family:var(--mono);font-size:12px}
.tblwrap{overflow:auto;border:1px solid var(--border);border-radius:8px;margin:8px 0;max-height:420px}
table{border-collapse:collapse;width:100%;font-family:var(--mono);font-size:12px}
th,td{border:1px solid var(--border);padding:6px 10px;text-align:left;white-space:nowrap;
max-width:460px;overflow:hidden;text-overflow:ellipsis}
th{background:var(--panel2);position:sticky;top:0}
.subh{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--accent);margin:10px 0 6px}
.bar{display:flex;align-items:center;gap:10px;margin:4px 0;font-size:12px}
.bk{font-family:var(--mono);flex:0 0 42%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bt{flex:1;background:var(--bg);border:1px solid var(--border);border-radius:4px;height:15px;overflow:hidden}
.bf{display:block;height:100%;background:var(--accent);opacity:.85}
.bn{font-family:var(--mono);color:var(--muted);min-width:42px;text-align:right}
.tag{font-family:var(--mono);font-size:10px;border:1px solid var(--border);border-radius:4px;padding:1px 6px}
.tag.int{color:#56d364;border-color:#3fb950}.tag.ext{color:#ff7b72;border-color:#f85149}
.mk{display:flex;gap:12px;align-items:flex-start;border-bottom:1px solid var(--border);padding:9px 0}
.badge{font-family:var(--mono);font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;border:1px solid var(--border);white-space:nowrap}
.badge-pendiente{color:#e3b341;border-color:#e3b341}.badge-TP{color:#ff7b72;border-color:#f85149}
.badge-FP{color:#56d364;border-color:#3fb950}.badge-descartado{color:var(--muted)}
.note{font-size:12px;margin-top:3px}
footer{max-width:1100px;margin:30px auto 0;padding:16px 24px;border-top:1px solid var(--border);
color:var(--muted);font-size:12px;text-align:center}
footer b{color:var(--accent)}
@media print{body{background:#fff;color:#000}details{break-inside:avoid}}
"""


def _persist_section(items: list) -> str:
    if not items:
        return ""
    rows = "".join(
        f'<tr><td>{_e(i.get("ts"))}</td><td><b>{_e(i.get("ptype"))}</b></td>'
        f'<td>{_e(i.get("detail"))}</td><td>{_e(i.get("user"))}</td></tr>'
        for i in items)
    return (f'<details><summary>Persistence <span class="pill">{len(items)} '
            f'signal(s)</span></summary><div class="tblwrap"><table><thead><tr>'
            f'<th>ts</th><th>type</th><th>detail</th><th>user</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div></details>')


def _logons_section(logons: list) -> str:
    if not logons:
        return ""
    failed = [l for l in logons if l.get("failed")]
    rows = "".join(
        f'<tr><td>{_e(l.get("ts"))}</td><td>{_e(l.get("action"))}</td>'
        f'<td>{_e(l.get("user"))}</td><td>{_e(l.get("logon_type"))}</td>'
        f'<td>{_e(l.get("src_ip"))}</td><td>{_e(l.get("host"))}</td></tr>'
        for l in logons[:200])
    return (f'<details><summary>Logons <span class="pill">{len(logons)} events · '
            f'{len(failed)} failed</span></summary><div class="tblwrap"><table><thead>'
            f'<tr><th>ts</th><th>action</th><th>user</th><th>type</th><th>source IP</th>'
            f'<th>host</th></tr></thead><tbody>{rows}</tbody></table></div></details>')


def build(meta: dict, dashboard: dict, sigma: Optional[dict],
          lol: dict, lol_labels: dict, marks: list,
          persist: Optional[list] = None, logons: Optional[list] = None) -> str:
    dist = dashboard.get("distinct", {})
    rng = (f'{dashboard.get("ts_min")} → {dashboard.get("ts_max")}'
           if dashboard.get("ts_min") else "no timestamps")
    nfind = len(sigma["findings"]) if sigma else 0
    nlol = sum(len(r.get("findings", [])) for r in (lol or {}).values())
    tiles = "".join([
        _tile(dashboard.get("total", 0), "events"),
        _tile(dist.get("source", 0), "channels"),
        _tile(dist.get("host", 0), "hosts"),
        _tile(dist.get("ip", 0), "distinct IPs"),
        _tile(nfind, "Sigma findings"),
        _tile(nlol, "LOL findings"),
        _tile(len(marks), "triage marks"),
    ])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(meta.get('title', 'WinHound report'))}</title><style>{_CSS}</style></head>
<body>
<header><h1>&#128302; WinHound — Windows forensic case report</h1>
<div class="sub">generated {_e(meta.get('generated'))} · case: {_e(meta.get('case') or 'in-memory')}
 · time range (UTC): {_e(rng)}</div></header>
<main>
<div class="tiles">{tiles}</div>
{_sigma_section(sigma)}
{_lol_section(lol, lol_labels)}
{_persist_section(persist or [])}
{_logons_section(logons or [])}
{_ip_section('Top destination IPs', dashboard.get('top_dst_ip', []))}
{_ip_section('Top source IPs', dashboard.get('top_src_ip', []))}
{_marks_section(marks)}
</main>
<footer>&#128302; WinHound · report made by <b>gmzpt</b><br>
<span class="small">IP Geolocation by DB-IP (https://db-ip.com)</span></footer>
</body></html>"""


def generated_now() -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
