# Query language

The Explorer search box speaks one query language — the same in WinHound and Longanizer.
Field names and values ignore case.

## Field operators

The two to remember:

| | Means | Example |
|---|---|---|
| `field=value` | **equal** — the exact value | `user=LocalSystem` |
| `field:value` | **contains** | `image:powershell` |

**Numbers and codes are always exact**, with either operator: `eid`, `record_id` and `logon_type`.
So `eid:6` and `eid=6` are the same and never match 4661. Spaces around the operator are fine:
`EventID = 6`, `eid: 6`.

| Syntax | Means | Example |
|---|---|---|
| `field!=value` | not equal (same as `-field=value`) | `user!=LocalSystem` |
| `field>N` `>=` `<` `<=` | compare numbers and dates | `eid>=4600` · `ts>=2026-10-01` |
| `field=a,b,c` | any of several numbers / codes | `eid=4624,4625` |
| `field:*x*` | wildcards `*` and `?` over the whole value | `image:*\powershell.exe` |
| `field:/regex/` | regular expression on one field | `command_line:/-enc\s+\w+/` |
| `field:*` | the field has a value | `logon_type:*` |
| `field:-` | the field is empty or missing | `user:-` |
| `ts:2026-10-01` | a whole day (dates match by prefix) | `ts:2026-10-01 eid=4625` |
| `field contains value` | word form of `:` | `image contains psexec` |
| `field==value` | synonym of `=` (kept for old searches) | |

`=` takes the value literally, so a value with `*` or commas still matches exactly; wildcards and
regex need `:`.

## Free text and combining

| Syntax | Means |
|---|---|
| `mimikatz lsass` | free text: both words appear (AND) |
| `"access is denied"` | a literal phrase; quotes also let you search the words *and*, *or*, *not* |
| `/regex/` | a regular expression over the raw record |
| `a AND b` · `a b` | AND (the default) |
| `a OR b` | OR |
| `NOT a` · `-a` | NOT |
| `( … )` | grouping |

`AND`, `OR` and `NOT` are case-insensitive (`&&`, `||` and `!` work too). Example:

```text
(eid=4624 OR eid=4625) logon_type=3 NOT user:SYSTEM
```

## Field names

Field names ignore case, `_`, `-` and `.`, and the usual Windows names work:

| You type | Field |
|---|---|
| `EventID` · `event_id` · `id` | `eid` |
| `CommandLine` · `cmd` | `command_line` |
| `ParentImage` · `parent` | `parent_image` |
| `Image` · `process` · `NewProcessName` | `image` |
| `SourceIp` · `IpAddress` · `ip` | `src_ip` |
| `DestinationIp` · `dip` | `dst_ip` |
| `Computer` · `hostname` | `host` |
| `Channel` · `LogName` | `source` |
| `TargetFilename` · `target` | `target_filename` |
| `ImageLoaded` | `image_loaded` |
| `EventRecordID` | `record_id` |
| `TimeCreated` · `time` | `ts` |

**EventData keys** work by name too: `TargetObject:Run`, `ServiceName:mimi`.
`x:Key` (or `extra.Key`) forces an EventData key with its exact case. The full list of columns is in
the [data model](data-model.md).

## Mistakes are reported

- An **unknown field** shows a ⚠ warning and is searched as plain text, instead of returning
  nothing in silence. Paths such as `C:\Windows` and URLs are plain text without a warning.
- A **malformed query** — an unclosed quote or parenthesis, `OR` at the end, `eid=` with no value —
  says what is wrong.

The **regular expression** checkbox turns all of this off and treats the whole box as one regex
over the raw record.

## From the results

- **⊕ / ⊖** on any cell, or **Ctrl/⌘-click** (with **Shift** to exclude), adds `field=value`
  (or `-field=value`) to the query.
- A **facet** value adds `field=value` too.
