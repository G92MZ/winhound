"""Parseo y normalización de EVTX (Windows Event Logs) a la tabla `events`.

Usa la librería Rust `evtx` (PyEvtxParser.records_json), que devuelve un JSON por
registro con Event.System / Event.EventData. System va a columnas fijas; los
EventData más usados se promueven a columnas de primera clase y el resto va a
`extra`. El registro completo se guarda en `raw`.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Iterator, Optional

from evtx import PyEvtxParser

from .schema import Event

# Level de Windows -> etiqueta
_LEVEL = {0: "info", 1: "critical", 2: "error", 3: "warning", 4: "info",
          5: "verbose"}

# EventData -> atributo de columna de primera clase (varios alias por campo)
_FIRST_CLASS = {
    "Image": "image", "NewProcessName": "image",
    "CommandLine": "command_line",
    "ParentImage": "parent_image", "ParentProcessName": "parent_image",
    "OriginalFileName": "original_filename",
    "Hashes": "hashes", "Hash": "hashes",
    "TargetFilename": "target_filename",
    "ImageLoaded": "image_loaded",
    "LogonType": "logon_type",
    "DestinationIp": "dst_ip",
    "SourceIp": "src_ip", "IpAddress": "src_ip",
}


def _toint(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _text(v):
    if isinstance(v, dict):
        return v.get("#text")
    return v


def _parse_time(st: Optional[str]) -> Optional[datetime]:
    if not st:
        return None
    try:
        return datetime.fromisoformat(
            st.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return None


def classify(channel: Optional[str], eid: Optional[int]) -> str:
    """Etiqueta de logsource aproximada (informativa) por canal+EventID."""
    ch = (channel or "").lower()
    if "sysmon" in ch:
        return {1: "process_creation", 3: "network_connection", 6: "driver_load",
                7: "image_load", 8: "create_remote_thread", 10: "process_access",
                11: "file_event", 12: "registry_event", 13: "registry_event",
                14: "registry_event", 15: "file_event", 17: "pipe_created",
                18: "pipe_created", 22: "dns_query", 23: "file_delete",
                25: "process_tampering"}.get(eid, "sysmon")
    if "powershell" in ch:
        return "ps_script" if eid == 4104 else "powershell"
    if ch == "security":
        if eid == 4688:
            return "process_creation"
        if eid in (4624, 4625, 4634, 4647, 4648):
            return "logon"
        if eid in (4697,):
            return "service"
        return "security"
    if "security-auditing" in ch:
        return "security"
    return ch.split("/")[-1] or "windows"


def normalize(data: dict, src_file: str,
              rec_meta: Optional[dict] = None) -> Optional[Event]:
    container = data.get("Event", data)
    if not isinstance(container, dict):
        return None
    sysb = container.get("System") or {}
    edata = container.get("EventData")
    if not isinstance(edata, dict):
        # UserData u otros: mete todo en extra
        udata = container.get("UserData")
        edata = udata if isinstance(udata, dict) else {}

    prov = sysb.get("Provider") or {}
    prov_name = (prov.get("#attributes") or {}).get("Name") if isinstance(prov, dict) else None
    eid = _toint(_text(sysb.get("EventID")))
    tc = sysb.get("TimeCreated") or {}
    st = (tc.get("#attributes") or {}).get("SystemTime") if isinstance(tc, dict) else None
    sec = sysb.get("Security") or {}
    sid = (sec.get("#attributes") or {}).get("UserID") if isinstance(sec, dict) else None
    level = _toint(_text(sysb.get("Level")))

    e = Event()
    e.ts = _parse_time(st)
    if e.ts is None and rec_meta:
        e.ts = _parse_time((rec_meta.get("timestamp") or "").replace(" UTC", ""))
    e.source = sysb.get("Channel")
    e.host = sysb.get("Computer")
    e.program = prov_name
    e.eid = eid
    e.event = str(eid) if eid is not None else None
    e.level = _LEVEL.get(level)
    e.record_id = _toint(sysb.get("EventRecordID"))
    e.sid = sid
    e.src_file = src_file

    extra: dict = {}
    # EventData puede tener 'Data' como lista (sin nombre) -> va a extra tal cual
    for k, v in edata.items():
        attr = _FIRST_CLASS.get(k)
        if attr and getattr(e, attr) is None and isinstance(v, (str, int, float)):
            setattr(e, attr, str(v))
        else:
            extra[k] = v

    # usuario: nombre si lo trae, si no el SID
    e.user = (edata.get("SubjectUserName") or edata.get("TargetUserName")
              or edata.get("User") or edata.get("AccountName") or sid)
    if isinstance(e.user, dict):
        e.user = _text(e.user)

    # resumen legible para búsqueda/explorador
    e.message = (e.command_line or e.image or e.target_filename
                 or e.image_loaded or e.hashes or "")

    e.extra = json.dumps(extra, ensure_ascii=False, default=str) if extra else None
    e.raw = json.dumps(container, ensure_ascii=False, default=str)

    # Sigma: en Windows casi todo es atacable
    e.sigma_ok = 1
    e.sigma_logsource = classify(e.source, eid)
    return e


def iter_evtx(path: str) -> Iterator[Event]:
    """Itera un fichero .evtx y emite Events normalizados."""
    parser = PyEvtxParser(path)
    for rec in parser.records_json():
        try:
            data = json.loads(rec["data"])
        except (ValueError, KeyError):
            continue
        ev = normalize(data, src_file=path, rec_meta=rec)
        if ev is not None:
            yield ev


def count_records(path: str) -> int:
    n = 0
    for _ in PyEvtxParser(path).records_json():
        n += 1
    return n
