# Findings: web and firewall lab

Data: indexes `web_lab` (`web:access`) and `fw_lab` (`fw:traffic`) on a Splunk Cloud trial. Loaded and tested 30 Sep 2026.
Dashboards: [Web Application Threat Monitor](../dashboards/web-app-threat-monitor.json), [Firewall Traffic Monitor](../dashboards/firewall-traffic-monitor.json)

## 1. What the source data is

| Dataset | Events | Time span |
|---|---|---|
| `complex_log.csv` (web access) | 1,000 | 10 Jun 2025, 00:03 to 23:59 |
| `firewall_traffic_logs_large.csv` | 200 | 12 Jun 2025, 08:00 to 08:49 |

Both files are uniformly random synthetic data:

- **Web:** IP, method, path, status and user agent are independent of each other. All 24 client IPs make between 35 and 49 requests, error rates are similar for every user agent (24 to 34%), and rows are not in time order.
- **Firewall:** 11 internal sources and 10 internal destinations. 51% of connections are allowed, and every port is both allowed and blocked with no consistent rule (SSH/22 is allowed 32% of the time, HTTPS/443 71%).

There is no attack in either file, so any "attacker found" result from them alone would be made up. To test the detections, I added a set of clearly labelled attack scenarios on top. See [simulation/README.md](../simulation/README.md).

## 2. Baselines and thresholds

Every threshold was set after measuring the original (non-simulated) rows.

| Measure | Normal maximum | Threshold | Headroom |
|---|---|---|---|
| 404s per 5 min, all clients | 4 (99th percentile 3) | more than 20 | 5x |
| Distinct 404 paths per client per 5 min | 2 | 10 or more | 5x |
| 401s on `/login` | 0 | 20 per client in 10 min | n/a |
| 403s per client per 15 min | 2 | 5 in 30 min, plus a successful DELETE/PUT | 2.5x |
| Distinct ports per source/destination pair per 5 min | 2 | 15 or more | 7.5x |
| RDP connections per source per 5 min | 3 | 15 or more | 5x |
| Bytes per host pair per 10 min | 18.7 KB | 50 MB to an external IP | over 2,600x |

## 3. Detection results

| Detection | MITRE ATT&CK | What it caught | False positives |
|---|---|---|---|
| [Login brute force](../searches/detections/web/login_brute_force.spl) | T1110.001 | 150 failed logins from 203.0.113.50 in 10 min, followed by a successful login | 0 |
| [404 spike](../searches/detections/web/404_spike.spl) | T1595.003 | 91 404s in one 5-min window, 90 of them from 198.51.100.23 | 0 |
| [Content discovery](../searches/detections/web/content_discovery.spl) | T1595.003, T1083 | 20 missing paths probed (`/.env`, `/.git/config`, `/.aws/credentials`...) by a Nikto user agent | 0 |
| [Admin denied, then modified](../searches/detections/web/admin_denied_then_modified.spl) | T1078, T1485 | 12 x 403 on `/admin`, then 8 successful `DELETE /api/user` requests from curl | 0 |
| [Port scan](../searches/detections/network/port_scan.spl) | T1046 | 60 ports on 10.0.0.5 in 60 s; 80 and 443 allowed | 0 |
| [RDP brute force](../searches/detections/network/rdp_brute_force.spl) | T1110, T1021.001 | 40 attempts, 10 of them allowed, so severity is raised to high | 0 |
| [Large outbound transfer](../searches/detections/network/large_outbound_transfer.spl) | T1041, T1048 | 163.5 MB from 192.168.1.105 to 198.51.100.200 on 443 in 3 min | 0 |

All six simulated attacks were detected (the content scan triggers two detections), with no false positives on the 1,200 original events.

I also ran each scheduled alert in [savedsearches.conf](../alerts/savedsearches.conf) over its exact cron window. Each one fires in the window where its attack happened and returns nothing an hour earlier.

## 4. Findings in the original data

These come from the provided files, not the simulation.

1. **Admin endpoints accept destructive requests from scripts.** 19 DELETE or PUT requests to `/admin` or `/api/user` from curl or Postman returned 2xx, from 15 different internal IPs. `/admin` returned 200 to 60 requests overall. The endpoints need proper authentication and authorisation. Search: [scripted_admin_changes.spl](../searches/hunting/scripted_admin_changes.spl)
2. **RDP is allowed internally.** 21 connections to port 3389 were allowed from 9 different sources in 50 minutes. RDP should be limited to jump hosts.
3. **The firewall log contradicts itself.** 56 records are ICMP with a port number, which can't happen because ICMP has no ports. Every private `192.168.x` source is tagged with 5 or 6 different countries. Rules that depend on protocol or country from this log would be unreliable until the log pipeline is fixed. Search: [firewall_field_integrity.spl](../searches/data-quality/firewall_field_integrity.spl)

## 5. Limitations

- I chose the thresholds knowing what the simulated attacks looked like. The large margin over normal traffic helps, but real traffic needs a baseline of weeks, not one day.
- The `scenario` field is only used to evaluate results. No detection reads it.
- The lab data is from June 2025, so the alerts are defined but not switched on. A live alert looking at the last few minutes would never see this data.
