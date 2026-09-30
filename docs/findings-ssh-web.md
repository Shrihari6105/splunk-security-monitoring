# Findings: SSH and web traffic (tutorial data)

Data: index `project_1`, 21 to 28 Sep 2026. Queried 30 Sep 2026.
Dashboard: [SSH & Web Security Overview](../dashboards/ssh-web-security-overview.json)

## SSH

| Metric | Value |
|---|---|
| Failed logins | 33,069 |
| Successful logins | 1,599 |
| Unique source IPs with failures | 182 |
| Attempts on usernames that don't exist | 24,011 (73%) |

- Failures are spread evenly across the four hosts: `www1` 8.7k, `www3` 8.2k, `mailsv1` 8.1k, `www2` 8.0k.
- Most-targeted invalid usernames: `administrator`, `admin`, `operator`, `mailman`, `irc`. This is a dictionary attack pattern.
- Top brute-force sources ([ssh_brute_force.spl](../searches/detections/linux/ssh_brute_force.spl)):
  - `87.194.216.51`: 948 failures, 98 usernames
  - `211.166.11.101`: 743 failures
  - `128.241.220.82`: 622 failures
- Top source countries: United States, China, Russia, United Kingdom, South Korea.
- **No sign of compromise** ([ssh_login_after_failures.spl](../searches/detections/linux/ssh_login_after_failures.spl)). Every successful login came from one of three internal addresses (`10.3.10.46`, `10.2.10.163`, `10.1.10.172`). No brute-forcing IP ever logged in.

## Web

- 5,250 error responses (4xx/5xx) out of about 39,500 requests. The most common are 503, 408 and 500.
- [error_based_scanning.spl](../searches/detections/web/error_based_scanning.spl) flags clients with 20 or more errors. The top one is `87.194.216.51`: 142 errors across 12 URIs.

## Same attackers on both services

[ssh_and_web_same_source.spl](../searches/hunting/ssh_and_web_same_source.spl) found **152 IPs** with at least 50 failed SSH logins and at least 20 web errors. The top SSH brute-forcers are also the top web scanners, so this looks like the same actors probing both services.

## Next steps

- Deploy [props.conf](../configs/props-transforms/props.conf) so the `secure-2` fields are extracted at search time and the inline `rex` can go.
- Schedule the SSH detections as throttled alerts.
