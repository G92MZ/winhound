#!/usr/bin/env python3
"""Screenshots for the documentation site (docs/assets/shots/**.webp).

Starts WinHound on a throw-away case built from the bundled public samples
(samples/evtx-attack-samples.zip), writes a few small demo Sigma / LOL rules
(generic, invented for the screenshots — WinHound ships no rules), drives the
UI with Playwright and saves each view as WebP.

    pip install playwright pillow      # Chromium: python -m playwright install chromium
    python scripts/docs_screenshots.py           # all shots
    python scripts/docs_screenshots.py explorer  # only shots whose name starts with it

Nothing from a real case is ever used.
"""
from __future__ import annotations

import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "assets" / "shots"
SAMPLES = ROOT / "samples" / "evtx-attack-samples.zip"
W, H, DPR = 1440, 900, 1.25

# --- demo rules (generic, for the screenshots only) --------------------------
RULES_GENERAL = {
    "svc_mimikatz.yml": """
title: Service installed with a credential-dumping driver name
id: 3b3f2f0a-0d0e-4c71-9a10-000000000001
status: experimental
logsource: {product: windows, service: system}
detection:
  sel: {EventID: 7045}
  kw: {ServiceName|contains: ['mimi', 'mimidrv']}
  condition: sel and kw
level: high
tags: [attack.persistence, attack.t1543.003]
""",
    "ps_encoded.yml": """
title: PowerShell with an encoded command
id: 3b3f2f0a-0d0e-4c71-9a10-000000000002
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  img: {Image|endswith: ['\\\\powershell.exe', '\\\\pwsh.exe']}
  enc: {CommandLine|contains: [' -enc', ' -EncodedCommand', ' -e ']}
  condition: img and enc
level: medium
tags: [attack.execution, attack.t1059.001]
""",
    "lsass_access.yml": """
title: Process opened LSASS memory
id: 3b3f2f0a-0d0e-4c71-9a10-000000000003
status: experimental
logsource: {product: windows, category: process_access}
detection:
  sel: {TargetImage|endswith: '\\\\lsass.exe'}
  condition: sel
level: high
tags: [attack.credential_access, attack.t1003.001]
""",
    "failed_logons.yml": """
title: Failed logon
id: 3b3f2f0a-0d0e-4c71-9a10-000000000004
status: experimental
logsource: {product: windows, service: security}
detection:
  sel: {EventID: 4625}
  condition: sel
level: low
tags: [attack.credential_access, attack.t1110]
""",
    "schtask_created.yml": """
title: Scheduled task created
id: 3b3f2f0a-0d0e-4c71-9a10-000000000005
status: experimental
logsource: {product: windows, service: security}
detection:
  sel: {EventID: 4698}
  condition: sel
level: medium
tags: [attack.persistence, attack.t1053.005]
""",
    "rundll32_ordinal.yml": """
title: Rundll32 calling an export by ordinal
id: 3b3f2f0a-0d0e-4c71-9a10-000000000006
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  img: {Image|endswith: '\\\\rundll32.exe'}
  ord: {CommandLine|contains: ',#'}
  condition: img and ord
level: medium
tags: [attack.defense_evasion, attack.t1218.011]
""",
}
RULES_LOLBAS = {
    f"lolbas_{name}.yml": f"""
title: LOLBAS - {name}.exe used to {what}
id: 3b3f2f0a-0d0e-4c71-9a10-0000000001{i:02d}
status: experimental
logsource: {{product: windows, category: process_creation}}
detection:
  img: {{Image|endswith: '\\\\{name}.exe'}}
  cmd: {{CommandLine|contains: {json.dumps(args)}}}
  condition: img and cmd
level: medium
tags: [attack.defense_evasion, attack.{tech}]
"""
    for i, (name, what, args, tech) in enumerate([
        ("certutil", "download or decode", ["urlcache", "-decode", "-split"], "t1105"),
        ("regsvr32", "load a remote scriptlet", ["/i:http", "scrobj"], "t1218.010"),
        ("mshta", "run remote HTA/script", ["http", "javascript:", "vbscript:"], "t1218.005"),
        ("bitsadmin", "transfer a file", ["/transfer", "/addfile"], "t1197"),
        ("rundll32", "run script or export", ["javascript:", ",#", "url.dll"], "t1218.011"),
    ])
}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def post(base: str, path: str, body: dict) -> dict:
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.load(r)


def save(png: bytes, name: str) -> None:
    dest = OUT / f"{name}.webp"
    dest.parent.mkdir(parents=True, exist_ok=True)
    Image.open(io.BytesIO(png)).save(dest, "WEBP", quality=82, method=6)
    print(f"  {dest.relative_to(ROOT)}  ({dest.stat().st_size // 1024} KB)")


class Shooter:
    def __init__(self, page, base):
        self.pg, self.base = page, base

    def js(self, code: str, wait: float = 0.6):
        self.pg.evaluate(f"(async()=>{{ {code} }})()")
        time.sleep(wait)

    def tab(self, t: str, wait: float = 1.2):
        self.js(f"switchTab('{t}')", wait)

    def wait_for(self, sel: str, timeout: float = 60):
        self.pg.wait_for_selector(sel, timeout=timeout * 1000, state="attached")
        time.sleep(0.5)

    def shot(self, name: str, sel: str = "section.panel.active", max_h: int = H,
             top: bool = False, pad: int = 8):
        """top=True: from the tab bar down (tabs + start of the panel). The page
        header is left out: with many channels its counters take several lines."""
        if top:
            self.pg.evaluate("window.scrollTo(0,0)")
            time.sleep(0.3)
            y = self.pg.evaluate("document.querySelector('.tabs').getBoundingClientRect().top+scrollY") - 6
            clip = {"x": 0, "y": max(0, y), "width": W, "height": max_h}
        else:
            el = self.pg.locator(sel).first
            el.scroll_into_view_if_needed()
            time.sleep(0.3)
            b = self.pg.evaluate(
                "(s)=>{const r=document.querySelector(s).getBoundingClientRect();"
                "return {x:r.x+scrollX,y:r.y+scrollY,w:r.width,h:r.height}}", sel)
            clip = {"x": max(0, b["x"] - pad), "y": max(0, b["y"] - pad),
                    "width": min(W, b["w"] + 2 * pad), "height": min(max_h, b["h"] + 2 * pad)}
        save(self.pg.screenshot(clip=clip, full_page=True), name)


def main(only: str = "") -> None:
    if not SAMPLES.exists():
        sys.exit(f"missing {SAMPLES}")
    tmp = Path(tempfile.mkdtemp(prefix="winhound-docs-"))
    try:
        with zipfile.ZipFile(SAMPLES) as z:
            z.extractall(tmp / "evtx")
        for folder, rules in (("general", RULES_GENERAL), ("lolbas", RULES_LOLBAS)):
            d = tmp / "rules" / folder
            d.mkdir(parents=True)
            for fn, txt in rules.items():
                (d / fn).write_text(txt.lstrip(), encoding="utf-8")

        port = free_port()
        base = f"http://127.0.0.1:{port}"
        env = dict(os.environ, PYTHONUNBUFFERED="1")
        srv = subprocess.Popen([sys.executable, "run.py", "--host", "127.0.0.1", "--port", str(port),
                                "--no-update", "--db", str(tmp / "case.duckdb")],
                               cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(120):
                try:
                    urllib.request.urlopen(base + "/", timeout=2)
                    break
                except OSError:
                    time.sleep(0.5)
            print("ingesting samples…")
            post(base, "/ingest/path", {"path": str(tmp / "evtx")})
            shoot(base, tmp, only)
        finally:
            srv.terminate()
            srv.wait(timeout=20)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def shoot(base: str, tmp: Path, only: str) -> None:
    def want(name: str) -> bool:
        return name.startswith(only)

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        pg = browser.new_page(viewport={"width": W, "height": H}, device_scale_factor=DPR)
        pg.goto(base + "/", wait_until="networkidle")
        time.sleep(1.5)
        s = Shooter(pg, base)

        # --- Getting started ---------------------------------------------------
        if want("start"):
            s.tab("landing")
            s.shot("start/load", top=True, max_h=820)

        # --- Explorer ----------------------------------------------------------
        if want("explorer") or want("home"):
            s.tab("explorer")
            s.js("showTimeline()", 2.5)
            s.shot("explorer/toolbar", top=True, max_h=1000)
            s.shot("home/explorer", "#hits", max_h=700)
            s.shot("explorer/timeline", "#hits", max_h=700)
            pg.fill("#q", "EventID = 7045 mimikatz")
            s.js("doSearch()", 2)
            s.js("document.querySelector('details.qhelp').open=true", 0.4)
            s.shot("explorer/query-cheatsheet", ".toolbar", max_h=1100)
            s.js("document.querySelector('details.qhelp').open=false", 0.3)
            pg.fill("#q", "eid=4624 logon_type=3")
            s.js("doSearch()", 2)
            td = pg.locator("#serows tr.hitrow >> nth=0 >> td.c-user")
            td.scroll_into_view_if_needed()
            td.hover()
            time.sleep(0.5)
            box = pg.locator("#hits").bounding_box()
            save(pg.screenshot(clip={"x": 0, "y": box["y"] + pg.evaluate("scrollY") - 10, "width": W, "height": 260},
                               full_page=True), "explorer/cell-filter")
            s.js("document.getElementById('facfield').value='user'; loadFacets()", 1.5)
            s.shot("explorer/facets", "div:has(> #fac_out)", max_h=560)
            first = pg.evaluate("ROWMAP && Object.keys(ROWMAP)[0]")
            s.js(f"openCtx({first})", 2)
            s.shot("explorer/context", "#gotoout", max_h=640)
            s.js("toggleColsPanel()", 0.8)
            s.shot("explorer/columns", "#colspanel", max_h=560)
            s.js("toggleColsPanel()", 0.4)

        # --- Overview + report -------------------------------------------------
        if want("overview"):
            s.tab("dash")
            s.js("loadDash()", 3)
            s.shot("overview/overview", top=True, max_h=900)

        # --- IOCs --------------------------------------------------------------
        if want("iocs"):
            s.tab("iocx", 4)
            s.wait_for("#iocx_out .iocard")
            s.shot("iocs/extractor", top=True, max_h=900)
            s.tab("ioc")
            ips = pg.evaluate("fetch('/query',{method:'POST',headers:{'Content-Type':'application/json'},"
                              "body:JSON.stringify({sql:\"SELECT DISTINCT src_ip FROM events WHERE src_ip IS NOT NULL "
                              "AND src_ip NOT LIKE '127.%' LIMIT 3\"})}).then(r=>r.json()).then(j=>j.rows.map(r=>r[0]))")
            pg.fill("#ioc_in", "\n".join(ips + ["mimikatz.exe", "psexesvc", "203.0.113.200"]))
            s.js("runIoc()", 3)
            s.shot("iocs/sweep", top=True, max_h=820)

        # --- SQL ---------------------------------------------------------------
        if want("sql"):
            s.tab("sql")
            pg.fill("#sqltext", "-- failed logons grouped by source IP\n"
                    "SELECT src_ip, count(*) AS n FROM events\n"
                    "WHERE source='Security' AND eid=4625 AND src_ip IS NOT NULL\n"
                    "GROUP BY src_ip ORDER BY n DESC;")
            s.js("runSql()", 2.5)
            s.shot("sql/sql", top=True, max_h=820)

        # --- Sigma, LOL, Lookalike, ATT&CK -------------------------------------
        if want("detect"):
            s.tab("sigma")
            pg.fill("#sg_path", str(tmp / "rules" / "general"))
            s.js("await sigmaLoad()", 2)
            s.js("await sigmaRun()", 2)
            s.wait_for("#sg_out .sghits, #sg_out details")
            s.js("const d=document.querySelector('#sg_out details'); if(d) d.open=true;"
                 "const b=document.querySelector('#sg_out .sgexp, #sg_out summary'); if(b && !d) b.click();", 1)
            s.shot("detect/sigma", top=True, max_h=1000)
            s.tab("lol_lolbas")
            pg.fill("#lol_lolbas_path", str(tmp / "rules" / "lolbas"))
            s.js("await lolLoad('lolbas')", 2)
            s.js("await lolRun('lolbas')", 3)
            s.shot("detect/lolbas", top=True, max_h=1000)
            s.tab("lookalike")
            s.js("await lkRun()", 3)
            s.shot("detect/lookalike", top=True, max_h=760)
            s.tab("attack", 3)
            s.shot("detect/attack", top=True, max_h=820)

        # --- Hunting -----------------------------------------------------------
        if want("hunt"):
            s.tab("proctree", 2)
            pg.fill("#pt_img", "powershell.exe")
            s.js("await loadProctree()", 3)
            s.shot("hunt/proctree", top=True, max_h=900)
            for t, name in (("logons", "logons"), ("persist", "persistence"),
                            ("powershell", "powershell"), ("network", "network")):
                s.tab(t, 3)
                s.shot(f"hunt/{name}", top=True, max_h=820)

        # --- Marks + report ----------------------------------------------------
        if want("marks"):
            ids = pg.evaluate("fetch('/query',{method:'POST',headers:{'Content-Type':'application/json'},"
                              "body:JSON.stringify({sql:\"SELECT id FROM events WHERE eid=7045 LIMIT 3\"})})"
                              ".then(r=>r.json()).then(j=>j.rows.map(r=>r[0]))")
            for i, (st, note) in zip(ids, [("TP", "Driver service installed from a temp folder"),
                                          ("pendiente", None), ("FP", "Known admin tool")]):
                post(base, "/marks", {"event_id": i, "estado": st, "nota": note})
            s.tab("marks", 2)
            s.shot("marks/marks", top=True, max_h=760)
            pg.goto(base + "/report", wait_until="networkidle")
            time.sleep(1)
            pg.evaluate("document.querySelectorAll('details').forEach((d,i)=>d.open=i<2)")
            save(pg.screenshot(clip={"x": 0, "y": 0, "width": W, "height": 900}, full_page=True), "marks/report")
            pg.goto(base + "/", wait_until="networkidle")
            time.sleep(1.5)

        # --- AI & MCP ----------------------------------------------------------
        if want("ai"):
            s.tab("ai", 1)
            s.shot("ai/ai", top=True, max_h=760)
            s.tab("mcp", 1.5)
            s.shot("ai/mcp", top=True, max_h=760)

        browser.close()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "")
