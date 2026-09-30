# Splunk Security Monitoring

Security monitoring and threat detection with Splunk — SPL detection searches, SOC dashboards, alerts, and log-source configuration.

## Goals

- Ingest and normalise security-relevant logs (Windows Event Logs, Linux auth/syslog, firewall, web server)
- Write SPL detections mapped to MITRE ATT&CK
- Build SOC dashboards for triage and investigation
- Configure alerts with sensible thresholds and throttling

## Repository layout

| Path | Contents |
|---|---|
| `searches/detections/` | Detection searches (`.spl`), one per use case |
| `searches/hunting/` | Ad-hoc threat-hunting queries |
| `dashboards/` | Dashboard Studio JSON / Simple XML exports |
| `alerts/` | Saved-search / alert definitions (`savedsearches.conf` snippets) |
| `apps/local/` | Custom Splunk app configs |
| `configs/inputs/` | `inputs.conf` examples for forwarders |
| `configs/props-transforms/` | Field extractions (`props.conf`, `transforms.conf`) |
| `sample-data/` | Sanitised sample logs for testing |
| `docs/` | Setup notes, architecture, write-ups |
| `screenshots/` | Dashboard and result screenshots |

## Detection index

| ID | Detection | Data source | MITRE ATT&CK |
|---|---|---|---|
| D001 | [Brute-force login attempts](searches/detections/D001_bruteforce_login.spl) | Windows Security (4625) | T1110 |

## Environment

- Splunk Enterprise (free/trial) or Splunk Cloud trial
- Universal Forwarder on monitored hosts

## Setup

See [docs/setup.md](docs/setup.md).

## Author

Shrihari — [@Shrihari6105](https://github.com/Shrihari6105)
