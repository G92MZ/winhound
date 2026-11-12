# SQL recipes

Paste them into the [SQL](../investigate/sql.md) tab.

```sql
-- Office spawning a shell or a LOLBin
SELECT ts, host, image, command_line FROM events
WHERE eid = 1 AND source LIKE '%Sysmon%'
  AND lower(parent_image) LIKE '%\winword.exe'
ORDER BY ts;
```

```sql
-- failed logons grouped by source IP
SELECT src_ip, count(*) AS n FROM events
WHERE source = 'Security' AND eid = 4625
GROUP BY src_ip ORDER BY n DESC;
```

```sql
-- driver loads (BYOVD hunting) with hashes
SELECT ts, host, image_loaded, hashes FROM events
WHERE source LIKE '%Sysmon%' AND eid = 6
ORDER BY ts;
```

```sql
-- a value that lives in EventData (extra)
SELECT ts, image, extra->>'TargetObject' AS target
FROM events WHERE eid = 13
ORDER BY ts;
```

```sql
-- network connections to a destination port
SELECT ts, image, dst_ip, extra->>'DestinationPort' AS port
FROM events WHERE eid = 3 AND source LIKE '%Sysmon%'
ORDER BY ts;
```

```sql
-- services installed, with their binary
SELECT ts, host, extra->>'ServiceName' AS service, extra->>'ImagePath' AS path
FROM events WHERE source = 'System' AND eid = 7045
ORDER BY ts;
```

!!! tip "`extra` inside expressions"
    Wrap `extra->>'Key'` in parentheses when it is part of an expression —
    `(extra->>'TargetObject') ILIKE '%\Run\%'` — or use
    `json_extract_string(extra, '$.TargetObject')`.
