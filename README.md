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
| `sample-data/` | Lab datasets and simulated attack CSVs |
| `simulation/` | Deterministic attack-simulation generators (Python + SPL) |
| `docs/` | Setup notes, architecture, write-ups |
| `screenshots/` | Dashboard and result screenshots |

## Detection index

| ID | Detection | Data source | MITRE ATT&CK | Status |
|---|---|---|---|---|
| D001 | [Brute-force login attempts](searches/detections/D001_bruteforce_login.spl) | Windows Security (4625) | T1110 | Written, no Windows data yet |
| D002 | [SSH brute force](searches/detections/D002_ssh_bruteforce.spl) | Linux secure log | T1110.001 | Validated |
| D003 | [SSH success after repeated failures](searches/detections/D003_ssh_success_after_failures.spl) | Linux secure log | T1110 / T1078 | Validated (0 hits) |
| D004 | [Web scanning / probing](searches/detections/D004_web_error_scanning.spl) | Apache access log | T1595 | Validated |

| D005 | [Web login brute force](searches/detections/D005_web_login_bruteforce.spl) | Web access (lab) | T1110.001 | Validated: 1 TP, 0 FP |
| D006 | [HTTP 404 spike](searches/detections/D006_web_404_spike.spl) | Web access (lab) | T1595.003 | Validated: 1 TP, 0 FP |
| D007 | [Content discovery](searches/detections/D007_web_content_discovery.spl) | Web access (lab) | T1595.003 / T1083 | Validated: 1 TP, 0 FP |
| D008 | [Admin denied then modified](searches/detections/D008_web_admin_denied_then_modified.spl) | Web access (lab) | T1078 / T1485 | Validated: 1 TP, 0 FP |
| D009 | [Port scan](searches/detections/D009_fw_port_scan.spl) | Firewall (lab) | T1046 | Validated: 1 TP, 0 FP |
| D010 | [RDP brute force](searches/detections/D010_fw_rdp_bruteforce.spl) | Firewall (lab) | T1110 / T1021.001 | Validated: 1 TP, 0 FP |
| D011 | [Large outbound transfer](searches/detections/D011_fw_large_outbound_transfer.spl) | Firewall (lab) | T1041 / T1048 | Validated: 1 TP, 0 FP |
| DQ001 | [Firewall field integrity](searches/detections/DQ001_fw_field_integrity.spl) | Firewall (lab) | Data quality | 56 impossible records |

Hunting: [H001 — same source attacking SSH and web](searches/hunting/H001_ssh_and_web_same_source.spl) · [H002 — scripted clients changing admin endpoints](searches/hunting/H002_scripted_admin_changes.spl)

Alerts and scheduled report: [alerts/savedsearches.conf](alerts/savedsearches.conf) (throttled, severity-rated)

## Dashboards

| Dashboard | Panels | Export |
|---|---|---|
| Web App Threat Monitor v2 | KPIs, status-class trend, web detections fired, top 404 clients, browser vs scripted, /admin access, posture table | [web-app-threat-monitor-v2.json](dashboards/web-app-threat-monitor-v2.json) |
| Firewall Traffic Monitor | KPIs, allowed/blocked trend, firewall detections fired, top ports, RDP sources, data-quality table | [firewall-traffic-monitor.json](dashboards/firewall-traffic-monitor.json) |
| SSH & Web Security Overview | 4 KPIs, auth trend, failures by host, brute-force sources, attacker countries, targeted usernames, web errors, web scanners, compromise check | [ssh-web-security-overview.json](dashboards/ssh-web-security-overview.json) |

Findings: [SSH & web (tutorial data)](docs/findings.md) · [Web & firewall lab: detection matrix](docs/lab-detection-results.md) · [Review of my earlier IBM assessment](docs/ibm-assessment-review.md)

## Data

Splunk Cloud trial, index `project_1` — the Splunk tutorial dataset (Buttercup Games), 21–28 Sep 2026:

| Sourcetype | Events | Content |
|---|---|---|
| `secure-2` | ~40k | Linux SSH auth logs from `mailsv1`, `www1-3` |
| `access_combined_wcookie` | ~39.5k | Apache web access logs |
| `vendor_sales` | ~30k | Retail sales (not security-relevant) |

Lab indexes (June 2025 synthetic data plus a labelled [attack simulation](simulation/README.md)):

| Index / sourcetype | Events | Source |
|---|---|---|
| `web_lab` / `web:access` | 1,000 + 261 simulated | `sample-data/complex_log.csv` |
| `fw_lab` / `fw:traffic` | 200 + 112 simulated | `sample-data/firewall_traffic_logs_large.csv` |

## Environment

- Splunk Enterprise (free/trial) or Splunk Cloud trial
- Universal Forwarder on monitored hosts

## Setup

See [docs/setup.md](docs/setup.md).

## Author

Shrihari — [@Shrihari6105](https://github.com/Shrihari6105)
