WinHound — bundled sample EVTX
=============================

evtx-attack-samples.zip contains 562 Windows .evtx logs covering a broad range
of attacker techniques (Sysmon + native Windows channels: Security, System,
PowerShell/Operational, TaskScheduler, WMI-Activity, Bits-Client, etc.).

These are the default samples used to develop and test WinHound. Source:
EVTX-ATTACK-SAMPLES by @sbousseaden (https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).

How to load them
-----------------
Option A — unzip, then load the folder (recommended):
  1. Extract evtx-attack-samples.zip  ->  gives an  evtx-attack-samples/  folder.
  2. In the app, open the "Load" tab and point "load from a server path" at that
     folder, OR drag-and-drop the folder in the upload box.

Option B — load the .zip directly:
  WinHound ingests .zip/.tar.gz archives recursively, so you can point the Load
  tab straight at evtx-attack-samples.zip and it will read every .evtx inside.

Everything in the app (Explorer context, Sigma, LOL tabs, Proc tree, Logons,
Persistence, PowerShell, Lookalike) has been tested against this dataset.
