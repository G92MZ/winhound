"""Esquema normalizado para eventos de Windows (EVTX).

Cada registro EVTX se normaliza a un Event con estos campos. Los campos de
`System` van a columnas fijas; los de `EventData` más usados se promueven a
columnas de "primera clase" (orden/filtro rápido) y el RESTO va a `extra`
(JSON, consultable con extra->>'Campo' y activable como columna dinámica en el
Explorador). El registro completo se guarda en `raw` (JSON).
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional


COLUMNS: list[tuple[str, str]] = [
    ("ts", "TIMESTAMP"),            # System.TimeCreated.SystemTime (UTC)
    ("source", "VARCHAR"),         # Channel completo (p.ej. Microsoft-Windows-Sysmon/Operational)
    ("host", "VARCHAR"),           # Computer
    ("program", "VARCHAR"),        # Provider Name
    ("event", "VARCHAR"),          # EventID como texto (para mostrar)
    ("eid", "INTEGER"),            # EventID numérico (filtro/orden rápido)
    ("level", "VARCHAR"),          # Level normalizado (info/warning/error/critical/verbose)
    ("user", "VARCHAR"),           # usuario resuelto (SubjectUserName/TargetUserName o SID)
    ("sid", "VARCHAR"),            # SID si el evento lo trae
    ("src_ip", "VARCHAR"),         # SourceIp / IpAddress
    ("dst_ip", "VARCHAR"),         # DestinationIp (Sysmon EID3)
    # --- EventData promovidos (primera clase) ---
    ("image", "VARCHAR"),          # Image / NewProcessName
    ("command_line", "VARCHAR"),   # CommandLine
    ("parent_image", "VARCHAR"),   # ParentImage / ParentProcessName
    ("original_filename", "VARCHAR"),  # OriginalFileName
    ("hashes", "VARCHAR"),         # Hashes
    ("target_filename", "VARCHAR"),    # TargetFilename
    ("image_loaded", "VARCHAR"),   # ImageLoaded
    ("logon_type", "VARCHAR"),     # LogonType
    # --- metadatos ---
    ("record_id", "BIGINT"),       # EventRecordID
    ("message", "VARCHAR"),        # resumen legible (CommandLine/target/etc.) para búsqueda
    ("extra", "JSON"),             # resto de EventData (+ algún System); extra->>'Campo'
    ("src_file", "VARCHAR"),       # fichero .evtx de origen
    ("raw", "VARCHAR"),            # registro completo (JSON)
    # --- Sigma ---
    ("sigma_ok", "INTEGER"),
    ("sigma_logsource", "VARCHAR"),
]

COLUMN_NAMES = [c[0] for c in COLUMNS]


@dataclass
class Event:
    ts: Optional[datetime] = None
    source: Optional[str] = None
    host: Optional[str] = None
    program: Optional[str] = None
    event: Optional[str] = None
    eid: Optional[int] = None
    level: Optional[str] = None
    user: Optional[str] = None
    sid: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    image: Optional[str] = None
    command_line: Optional[str] = None
    parent_image: Optional[str] = None
    original_filename: Optional[str] = None
    hashes: Optional[str] = None
    target_filename: Optional[str] = None
    image_loaded: Optional[str] = None
    logon_type: Optional[str] = None
    record_id: Optional[int] = None
    message: Optional[str] = None
    extra: Optional[str] = None
    src_file: Optional[str] = None
    raw: Optional[str] = None
    sigma_ok: Optional[int] = None
    sigma_logsource: Optional[str] = None

    def as_row(self) -> tuple:
        d = asdict(self)
        return tuple(d[name] for name in COLUMN_NAMES)
