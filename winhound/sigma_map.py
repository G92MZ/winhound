"""Mapeo Sigma (Windows) -> SQL sobre la tabla `events` de EVTX.

Sin pySigma. La taxonomía es la de Sysmon/Windows (Image, CommandLine,
ParentImage, Hashes, TargetFilename, ImageLoaded, …). `Channel` -> source,
`EventID` -> eid, `Provider` -> program. `process_creation` cubre Sysmon EID1
y Security 4688 (alias NewProcessName/ParentProcessName). Lo no mapeado cae a
(extra->>'Campo'); un campo ausente da NULL (no casa).
"""
from __future__ import annotations

import re
from typing import Optional

_SYS = "ev.source LIKE '%Sysmon%'"
_PS = "ev.source LIKE '%PowerShell%'"

# Predicados por logsource Sigma (alias de tabla: ev)
LOGSOURCE_PREDICATES: dict[str, str] = {
    "windows/process_creation": f"(({_SYS} AND ev.eid=1) OR (ev.source='Security' AND ev.eid=4688))",
    "windows/image_load":        f"({_SYS} AND ev.eid=7)",
    "windows/driver_load":       f"({_SYS} AND ev.eid=6)",
    "windows/network_connection": f"(({_SYS} AND ev.eid=3) OR (ev.source='Security' AND ev.eid=5156))",
    "windows/dns_query":         f"({_SYS} AND ev.eid=22)",
    "windows/registry_event":    f"({_SYS} AND ev.eid IN (12,13,14))",
    "windows/registry_add":      f"({_SYS} AND ev.eid=12)",
    "windows/registry_set":      f"({_SYS} AND ev.eid=13)",
    "windows/registry_delete":   f"({_SYS} AND ev.eid=14)",
    "windows/file_event":        f"({_SYS} AND ev.eid IN (11,15,26))",
    "windows/file_delete":       f"({_SYS} AND ev.eid IN (23,26))",
    "windows/create_stream_hash": f"({_SYS} AND ev.eid=15)",
    "windows/create_remote_thread": f"({_SYS} AND ev.eid=8)",
    "windows/process_access":    f"({_SYS} AND ev.eid=10)",
    "windows/raw_access_thread": f"({_SYS} AND ev.eid=9)",
    "windows/pipe_created":      f"({_SYS} AND ev.eid IN (17,18))",
    "windows/wmi_event":         f"({_SYS} AND ev.eid IN (19,20,21))",
    "windows/ps_script":         f"({_PS} AND ev.eid=4104)",
    "windows/ps_module":         f"({_PS} AND ev.eid=4103)",
    "windows/ps_classic_script": "ev.eid IN (400,500,501,600)",
    "windows/powershell":        _PS,
    "windows/sysmon":            _SYS,
    "windows/security":          "ev.source='Security'",
    "windows/system":            "ev.source='System'",
    "windows/application":       "ev.source='Application'",
    "windows/logon":             "(ev.source='Security' AND ev.eid IN (4624,4625,4634,4647,4648,4672))",
    "windows/taskscheduler":     "ev.source LIKE '%TaskScheduler%'",
    "windows/wmi":               "ev.source LIKE '%WMI-Activity%'",
    # genérico: cualquier evento (la detección filtra por Channel/EventID)
    "windows": "1=1",
}


def rule_logsource_key(product: Optional[str], category: Optional[str],
                       service: Optional[str]) -> Optional[str]:
    """logsource de la regla -> clave de predicado. Solo Windows (o sin product).
    Si no hay category/service con predicado propio, cae a 'windows' (genérico),
    de modo que una regla que solo filtra por Channel/EventID también se ejecuta."""
    p = (product or "").lower()
    c = (category or "").lower()
    s = (service or "").lower()
    if p and p != "windows":
        return None
    if c:
        key = f"windows/{c}"
        return key if key in LOGSOURCE_PREDICATES else "windows"
    if s:
        key = f"windows/{s}"
        return key if key in LOGSOURCE_PREDICATES else "windows"
    return "windows"


# ---------------------------------------------------------------------------
# Resolución de campos Sigma -> expresión SQL
# ---------------------------------------------------------------------------
_MAP = {
    # System / routing
    "Channel": "ev.source", "Provider": "ev.program", "Source": "ev.program",
    "SourceName": "ev.program", "Computer": "ev.host", "ComputerName": "ev.host",
    "Hostname": "ev.host", "EventID": "ev.eid", "Level": "ev.level",
    "RecordNumber": "ev.record_id", "EventRecordID": "ev.record_id",
    # process_creation / Sysmon
    "Image": "ev.image", "NewProcessName": "ev.image",
    "CommandLine": "ev.command_line", "ProcessCommandLine": "ev.command_line",
    "ParentImage": "ev.parent_image", "ParentProcessName": "ev.parent_image",
    "OriginalFileName": "ev.original_filename",
    "Hashes": "ev.hashes", "Hash": "ev.hashes",
    "TargetFilename": "ev.target_filename", "ImageLoaded": "ev.image_loaded",
    "LogonType": "ev.logon_type",
    "DestinationIp": "ev.dst_ip", "DestinationHostname": "ev.dst_ip",
    "SourceIp": "ev.src_ip", "IpAddress": "ev.src_ip", "SourceAddress": "ev.src_ip",
    # user
    "User": 'ev."user"', "SubjectUserName": 'ev."user"',
    "TargetUserName": 'ev."user"', "AccountName": 'ev."user"',
    "SubjectUserSid": "ev.sid", "TargetUserSid": "ev.sid", "Sid": "ev.sid",
}

_SAFE_KEY = re.compile(r"[^\w.\-]")


def _extra(field: str) -> str:
    key = _SAFE_KEY.sub("", field or "")
    return f"(ev.extra->>'{key}')" if key else "NULL"


def resolve_field(logsource_key: Optional[str], field: str) -> str:
    if field in _MAP:
        return _MAP[field]
    return _extra(field)


def resolve_field_for_process(field: str) -> str:
    return resolve_field(None, field)
