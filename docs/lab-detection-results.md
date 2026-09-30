# Lab results: web and firewall detections

Splunk Cloud trial, indexes `web_lab` (`web:access`) and `fw_lab` (`fw:traffic`). Loaded and run 30 Sep 2026.

## 1. What the source data actually is

| Dataset | Events | Time span | Finding |
|---|---|---|---|
| `complex_log.csv` | 1,000 | 10 Jun 2025, 00:03–23:59 | IP, method, path, status and user agent are statistically independent. Every one of the 24 IPs makes 35–49 requests, error rates are similar across all user agents (24–34%), and rows are not time-ordered. |
| `firewall_traffic_logs_large.csv` | 200 | 12 Jun 2025, 08:00–08:49 | 11 internal sources, 10 internal destinations, 51% allowed overall, and every port is both allowed and blocked with no consistent rule (e.g. SSH/22 allowed 32% of the time, HTTPS/443 71%). |

**Conclusion:** both files are uniformly random synthetic data with **no attack in them**. Any "attacker identified" claim from this data alone would be made up. Labelled attack scenarios were therefore added (see `simulation/README.md`) to test the detections.

## 2. Baselines (original rows only) and thresholds

| Measure | Baseline max | Detection threshold | Headroom |
|---|---|---|---|
| 404s per 5 min (all clients) | 4 (p99 3) | > 20 (D006) | 5× |
| Distinct 404 paths per client per 5 min | 2 | ≥ 10 (D007) | 5× |
| 401s on `/login` | 0 | ≥ 20 per client / 10 min (D005) | n/a |
| 403s per client per 15 min | 2 | ≥ 5 per 30 min, plus a successful DELETE/PUT (D008) | 2.5× |
| Distinct ports per src→dst per 5 min | 2 | ≥ 15 (D009) | 7.5× |
| RDP connections per source per 5 min | 3 | ≥ 15 (D010) | 5× |
| Bytes per host pair per 10 min | 18.7 KB | ≥ 50 MB to an external IP (D011) | >2,600× |

## 3. Detection matrix

| Detection | MITRE | Scenario | Result | False positives on 1,200 baseline events |
|---|---|---|---|---|
| D005 Web login brute force | T1110.001 | W1 | 150 failed logins from 203.0.113.50 in 10 min, then a successful login | 0 |
| D006 404 spike (improved IBM alert) | T1595.003 | W2 | 91 404s in one 5-min window, top client 198.51.100.23 (90) | 0 |
| D007 Content discovery | T1595.003 / T1083 | W2 | 20 distinct missing paths (`/.env`, `/.git/config`, `/.aws/credentials`…), Nikto UA | 0 |
| D008 Admin denied then modified | T1078 / T1485 | W3 | 12 × 403 on `/admin`, then 8 successful `DELETE /api/user` via curl | 0 |
| D009 Port scan | T1046 | F1 | 60 distinct ports on 10.0.0.5 in 60 s; 80 and 443 allowed | 0 |
| D010 RDP brute force | T1110 / T1021.001 | F2 | 40 attempts, **10 allowed** → severity high | 0 |
| D011 Large outbound transfer | T1041 / T1048 | F3 | 163.5 MB from 192.168.1.105 to 198.51.100.200:443 in 3 min | 0 |

**Result: 6/6 scenarios detected (W2 by two detections), 0 false positives.** Each scheduled alert in `alerts/savedsearches.conf` was also run in its exact cron window: it fires in the attack window and returns nothing an hour earlier.

## 4. Findings in the original (non-simulated) data

These are real observations about the provided files, not simulated:

1. **Destructive requests from scripted clients succeed (H002).** 19 `DELETE`/`PUT` requests to `/admin` or `/api/user` from curl/Postman returned 2xx, from 15 different internal IPs. `/admin` returned 200 to 60 requests overall across all methods. Recommendation: enforce authentication and authorisation on admin endpoints, and restrict non-browser clients.
2. **RDP is allowed internally.** 21 connections to 3389 were allowed, from 9 different sources, in 50 minutes. Recommendation: restrict RDP to jump hosts.
3. **The firewall log is internally inconsistent (DQ001).** 56 records are ICMP with a port number, which is impossible because ICMP has no ports. Every private `192.168.x` source carries 5–6 different GeoIP countries. Detections that rely on protocol or geo from this source would be unreliable. Recommendation: fix the log pipeline before trusting geo-based rules.

## 5. Caveats

- Thresholds were set with knowledge of the scenarios. The large headroom over baseline maxima is the defence against overfitting, but real traffic would need a longer baseline (weeks, not one day).
- The `scenario` field exists only for evaluation. The detections never use it.
- The lab data is historical (June 2025), so alerts are defined in `alerts/savedsearches.conf` but not enabled on the trial instance.

## Artefacts

- Dashboards: `dashboards/web-app-threat-monitor-v2.json`, `dashboards/firewall-traffic-monitor.json` (live in Splunk, shared app-wide)
- Detections: `searches/detections/D005`–`D011`, `DQ001`; hunt `searches/hunting/H002`
- Alerts and report: `alerts/savedsearches.conf`
- Simulation: `simulation/` (Python and SPL generators, verified identical)
