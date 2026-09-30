# Findings — project_1 (21–28 Sep 2026)

Source: [SSH & Web Security Overview](../dashboards/ssh-web-security-overview.json) dashboard and detections D002–D004, H001. Queried 30 Sep 2026.

## SSH

- **33,069 failed** vs **1,599 successful** SSH logins across 4 hosts (`www1` 8.7k failures, `www3` 8.2k, `mailsv1` 8.1k, `www2` 8.0k).
- **182 unique source IPs** failed to authenticate; **24,011 attempts (73%)** used usernames that don't exist on the host, a sign of dictionary attacks.
- Most-targeted invalid usernames: `administrator`, `admin`, `operator`, `mailman`, `irc`.
- Top brute-force sources (D002): `87.194.216.51` (948 failures, 98 usernames), `211.166.11.101` (743), `128.241.220.82` (622).
- By country: United States, China, Russia, United Kingdom, South Korea.
- **No compromise indicated (D003):** all successful logins came from 3 internal addresses (`10.3.10.46` djohnson, `10.2.10.163` nsharpe, `10.1.10.172` myuan). No brute-forcing IP ever authenticated.

## Web

- 5,250 error responses (4xx/5xx) out of ~39.5k requests; most common are 503, 408 and 500.
- D004 flags clients with ≥20 errors; top is `87.194.216.51` (142 errors across 12 URIs).

## Cross-vector (H001)

- **152 IPs** had both ≥50 failed SSH logins and ≥20 web errors. The top SSH brute-forcers are also the top web scanners, so these look like the same actors probing both services.

## Next steps

- Deploy `configs/props-transforms/props.conf` so `secure-2` fields are extracted at search time (removes inline `rex`).
- Turn D002–D004 into scheduled alerts with throttling (`alerts/`).
