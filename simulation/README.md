# Attack simulation

The two lab datasets in `sample-data/` (`complex_log.csv`, `firewall_traffic_logs_large.csv`) are **uniformly random synthetic logs**. Every field is statistically independent, so they contain no attack signal. To show that each detection works, a small set of **clearly labelled** attack scenarios is added on top.

| Scenario | Rows | Technique | Attacker IP (RFC 5737) |
|---|---|---|---|
| W1_login_bruteforce | 151 | 150 × 401 on `/login` in 10 min, then one 200 (T1110.001) | 203.0.113.50 |
| W2_content_scan | 90 | Nikto hitting 20 non-existent paths in 4.5 min (T1595.003) | 198.51.100.23 |
| W3_admin_abuse | 20 | 12 × 403 on `/admin`, then 8 successful `DELETE /api/user` with curl (T1078/T1485) | 192.0.2.77 |
| F1_port_scan | 60 | 60 distinct TCP ports on 10.0.0.5 in 60 s (T1046) | 203.0.113.77 |
| F2_rdp_bruteforce | 40 | 40 connections to 3389 in 4 min, 10 allowed (T1110/T1021.001) | 198.51.100.61 |
| F3_exfiltration | 12 | 163.5 MB from 192.168.1.105 to one external IP over 443 in 3 min (T1041/T1048) | 198.51.100.200 |

Every event carries a `scenario` field (`baseline` for original rows) and simulated events use `source="attack_simulation"`, so they can be filtered out or measured against at any time.

## Two equivalent generators

- `generate_attacks.py` writes `sample-data/sim_web_attacks.csv` and `sample-data/sim_fw_attacks.csv`.
- `sim_web.spl` / `sim_fw.spl` produce the same rows inside Splunk with `makeresults`. Both are deterministic, with no randomness. The SPL output was checked row for row against the Python CSVs (identical SHA-256).

## Loading into Splunk (what was done on the trial instance)

Indexes `web_lab` and `fw_lab` were created. Events were written with `collect` as `key=value` lines with the original timestamp:

```spl
| makeresults format=csv data="<CSV, max 30,000 characters per search>"
| eval scenario="baseline", _time=strptime(timestamp, "%Y-%m-%d %H:%M:%S")
| eval _raw=printf("%s client_ip=%s method=%s resource=\"%s\" status_code=%s bytes_sent=%s user_agent=\"%s\" scenario=%s", timestamp, client_ip, method, resource, status_code, bytes_sent, user_agent, scenario)
| collect index=web_lab sourcetype=web:access source="complex_log.csv" host="web01"
```

and `<contents of sim_web.spl> | eval _time=... | eval _raw=... | collect index=web_lab sourcetype=web:access source="attack_simulation"`. The firewall data follows the same pattern into `fw_lab` / `fw:traffic`.

A post-load check matched the source CSVs exactly: row counts, byte totals and status-code distribution per scenario.
