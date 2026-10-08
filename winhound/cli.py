"""CLI mínima de WinHound: ingesta EVTX a un caso DuckDB y consultas rápidas.

  python -m winhound.cli ingest <ruta> [--db caso.duckdb]
  python -m winhound.cli stats [--db caso.duckdb]
"""
from __future__ import annotations

import argparse
import json

from .ingest import ingest_path
from .store import EventStore


def main() -> None:
    ap = argparse.ArgumentParser(prog="winhound")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ing = sub.add_parser("ingest", help="ingesta EVTX (fichero/carpeta/comprimido)")
    ing.add_argument("path")
    ing.add_argument("--db", default="caso.duckdb")
    stt = sub.add_parser("stats", help="resumen del caso")
    stt.add_argument("--db", default="caso.duckdb")
    args = ap.parse_args()

    store = EventStore(args.db)
    if args.cmd == "ingest":
        res = ingest_path(store, args.path)
        ok = [r for r in res if r.get("events") is not None]
        print(f"{len(ok)} EVTX, {sum(r['events'] for r in ok)} events -> {args.db}")
    elif args.cmd == "stats":
        print(json.dumps(store.stats(), indent=2, default=str))


if __name__ == "__main__":
    main()
