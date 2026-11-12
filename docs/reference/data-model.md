# Data model

Every EVTX record becomes one row of the `events` table (DuckDB, timestamps in **UTC**):
System fields as columns, the most useful EventData fields **promoted** to columns, every other
EventData field in the `extra` JSON, and the whole record in `raw`.

| Column | From | |
|---|---|---|
| `ts` | `TimeCreated` | timestamp, UTC |
| `source` | `Channel` | Security, System, Microsoft-Windows-Sysmon/Operational… |
| `program` | `Provider` | |
| `event` · `eid` | `EventID` | text and integer |
| `host` | `Computer` | |
| `sid` | `Security.UserID` | |
| `level` | `Level` | |
| `user` | `SubjectUserName`, else `TargetUserName`, `User` or `AccountName`, else the SID | |
| `src_ip` · `dst_ip` | `SourceIp` / `IpAddress` · `DestinationIp` | |
| `image` · `command_line` · `parent_image` | `Image` / `NewProcessName` · `CommandLine` · `ParentImage` | |
| `original_filename` · `hashes` | `OriginalFileName` · `Hashes` | |
| `target_filename` · `image_loaded` | `TargetFilename` · `ImageLoaded` | |
| `logon_type` | `LogonType` | |
| `record_id` | `EventRecordID` | integer |
| `message` | | short summary: the command line, image, target file, loaded image or hashes |
| `extra` | the rest of EventData | JSON: `extra->>'TargetObject'` |
| `src_file` | | the `.evtx` it came from |
| `raw` | the whole record | JSON |

First-class columns versus `extra` is only about **speed** — a native column sorts and filters
faster on huge cases. Every field is reachable: by name in the search box (`TargetObject:Run`),
as a column from the **Columns** panel, or in SQL with `extra->>'Key'`.

## Without Sysmon

Native logs still work — 4688, 4624 / 4625, 7045, 4698… — with fewer fields (no hashes, no image
loads).
