# OT Access Assurance Lab

An offline, synthetic OT security and GRC evidence project based on a fictional
German Mittelstand packaging line. It demonstrates how access-event review can
use asset context, time windows, segmentation policy, and data-quality checks
without connecting to or changing a real industrial control system.

## Lab scenario

The lab inventory assigns example assets to illustrative Purdue levels:

| Purdue level | Example asset | Lab zone |
| --- | --- | --- |
| L4 | Corporate workstation | `enterprise_it` |
| L3.5 | Industrial DMZ jump host | `idmz` |
| L3 | Engineering workstations and historian | `ot_operations` |
| L2 | Packaging line HMI | `supervisory` |
| L1 | Packaging line PLC, inventory context only | `basic_control` |

Purdue levels are architectural labels in this exercise. ISA/IEC 62443 zones
and conduits are represented separately in the lab policy; the two concepts
are not treated as interchangeable. Purdue levels are also not mapped to
IEC 62443 security levels (SLs).

## What it analyzes

`ot_access_assurance.py` reads JSON Lines (`.jsonl`) access events and a local
asset/policy configuration. It identifies review scenarios such as:

- repeated failed logins for the same account, source, and target within a
  configurable time window;
- one source targeting several accounts (password-spray indicator);
- one account receiving attempts from several source IPs;
- a successful login following recent failures;
- cross-zone authentication events whose source/target pair is missing from the
  configured conduit policy;
- malformed events, unknown assets, and invalid timestamps or addresses.

Approved maintenance windows add a change reference to relevant findings;
they never automatically suppress an alert. The report includes event
references, applicable thresholds, a hash of the input file, and data-quality
issues without copying raw log lines.

## Run

Python 3.10 or later is required. The project uses only the Python standard
library.

```powershell
python .\ot_access_assurance.py
```

By default, the program reads `ot_auth_events.jsonl` and `ot_lab_config.json`,
then writes `ot_evidence_report.json`. Customize the paths with:

```powershell
python .\ot_access_assurance.py --input .\ot_auth_events.jsonl --config .\ot_lab_config.json --output .\ot_evidence_report.json
```

The time window, thresholds, asset inventory, allowed conduits, and approved
maintenance context are documented in `ot_lab_config.json`.

## Test

```powershell
python -m unittest discover -v
```

## Framework context and limits

This is a learning and portfolio project, **not** an IEC 62443 assessment,
certification, security-level calculation, or compliance verdict. Its
thresholds and allowed paths are illustrative lab policy and must not be used
as production defaults. Findings are indicators for a human reviewer, not
proof of malicious activity.

The lab is deliberately offline: it does not scan networks, connect to PLCs,
send control commands, block accounts, or change industrial equipment. The
bundled events and asset names are synthetic. Real OT deployment would require
site-specific risk assessment, safety and change-management approval, and
validation by qualified OT personnel.

The current detector analyzes authentication events only. It does not inspect
industrial protocols, validate firewall rules, prove the completeness of a
logging pipeline, or establish that a security control is operating
effectively.

## References

- [ISA/IEC 62443 series overview](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)
- [NIST SP 800-82 Rev. 3: Guide to Operational Technology Security](https://csrc.nist.gov/pubs/sp/800/82/r3/final)

The references provide context for OT security and the 62443 series; this
project does not reproduce or claim conformance with the standards.

## Kurzbeschreibung für Bewerbungen (Deutsch)

Ich habe ein offline betriebenes, synthetisches OT-Sicherheitslabor für eine
Verpackungslinie entwickelt. Das Python-Tool analysiert
Authentifizierungsereignisse in Zeitfenstern, berücksichtigt Anlagenzonen und
Wartungskontext und erstellt nachvollziehbare Prüfnachweise. Die Zuordnung zum
Purdue-Modell und die Zonen-/Conduit-Logik dienen der fachlichen Einordnung;
eine IEC-62443-Konformität wird nicht behauptet und reale Steuerungen werden
nicht angebunden.
