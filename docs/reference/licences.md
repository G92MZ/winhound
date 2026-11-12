# Licences and data

WinHound is licensed under the **Apache License 2.0** — free to use, modify and distribute
(including commercially); keep the copyright and `NOTICE`, and state your changes.
© 2026 Gregorio Moreno (gmzpt).

## Libraries

| Library | Used for | Licence |
|---|---|---|
| [evtx](https://github.com/omerbenamram/evtx) (Python bindings) | parsing `.evtx` | MIT / Apache-2.0 |
| [DuckDB](https://duckdb.org) | the case database | MIT |
| [FastAPI](https://fastapi.tiangolo.com) · [Uvicorn](https://www.uvicorn.org) | the web service | MIT · BSD-3-Clause |
| [pySigma](https://github.com/SigmaHQ/pySigma) *(optional)* | Sigma and LOL tabs | LGPL-2.1 |
| [maxminddb](https://github.com/maxmind/MaxMind-DB-Reader-python) *(optional)* | reading GeoIP databases | Apache-2.0 |
| [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) *(optional)* | the MCP server | MIT |

Optional packages are installed by you with `pip`, not shipped in the repository.

## Data

- **GeoIP** — IP geolocation by [DB-IP](https://db-ip.com) (DB-IP Lite, CC BY 4.0), downloaded
  on demand into `geoip_data/`.
- **Sample EVTX** — [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by
  @sbousseaden, in `samples/evtx-attack-samples.zip`.
- **Sigma and LOL rules** — none ship with WinHound; you load your own.
