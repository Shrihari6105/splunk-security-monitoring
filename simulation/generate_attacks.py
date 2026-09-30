"""Generate a labelled attack simulation on top of the lab datasets.

The source datasets (sample-data/complex_log.csv, sample-data/firewall_traffic_logs_large.csv)
are uniformly random synthetic logs with no attack signal. This script adds clearly labelled
attack scenarios so each detection can be shown firing. Every simulated row carries a
`scenario` value; baseline rows are loaded with scenario="baseline".

The output is fully deterministic (no randomness) and matches simulation/load_simulation.spl
row for row, so the same events can be generated inside Splunk or from this script.
Attacker IPs come from RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) so they can never be confused with real hosts.

Usage: python3 simulation/generate_attacks.py   (writes sample-data/sim_*.csv)
"""
import csv
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "sample-data"
ts = lambda base, s: (datetime.fromisoformat(base) + timedelta(seconds=s)).strftime("%Y-%m-%d %H:%M:%S")

WEB_PATHS = ["/.env", "/.git/config", "/wp-admin", "/wp-login.php", "/phpmyadmin", "/backup.zip", "/config.php",
             "/server-status", "/admin.php", "/.aws/credentials", "/api/v1/debug", "/actuator/env",
             "/cgi-bin/test.cgi", "/db.sql", "/old", "/test", "/console", "/.DS_Store", "/shell.php", "/uploads"]
FW_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389,
            5432, 5900, 5985, 6379, 8080, 8443, 9200, 27017] + [1024 + 7 * i for i in range(33)]

web, fw = [], []
# W1 - Credential brute force on /login (T1110.001): 150 failed POSTs in 10 min, then a success
for i in range(150):
    web.append([ts("2025-06-10 14:00:00", 4 * i), "203.0.113.50", "POST", "/login", 401, 200 + (i * 53) % 700, "python-requests/2.31.0", "W1_login_bruteforce"])
web.append([ts("2025-06-10 14:00:00", 604), "203.0.113.50", "POST", "/login", 200, 1840, "python-requests/2.31.0", "W1_login_bruteforce"])
# W2 - Content discovery scan (T1595.003): 90 requests for non-existent paths in 4.5 min -> 404 burst
for i in range(90):
    web.append([ts("2025-06-10 02:15:00", 3 * i), "198.51.100.23", "GET", WEB_PATHS[i % 20], 404, 180 + (i * 29) % 400, "Nikto/2.5.0", "W2_content_scan"])
# W3 - Admin abuse (T1078 / T1485): 403s on /admin, then successful DELETEs from a scripted client
for i in range(12):
    web.append([ts("2025-06-10 22:40:00", 20 * i), "192.0.2.77", "GET" if i % 2 == 0 else "DELETE", "/admin", 403, 210 + (i * 17) % 300, "curl/7.68.0", "W3_admin_abuse"])
for i in range(8):
    web.append([ts("2025-06-10 22:45:00", 15 * i), "192.0.2.77", "DELETE", "/api/user", 200, 350 + (i * 41) % 500, "curl/7.68.0", "W3_admin_abuse"])

# F1 - Port scan (T1046): one external source probes 60 distinct TCP ports on one host in 60 s
for i, p in enumerate(FW_PORTS):
    fw.append([ts("2025-06-12 08:52:00", i), "203.0.113.77", "10.0.0.5", 60, "allowed" if p in (80, 443) else "blocked", p, "TCP", "RU", "F1_port_scan"])
# F2 - RDP brute force (T1110 / T1021.001): 40 connections to 3389 in 4 min, every 4th allowed
for i in range(40):
    fw.append([ts("2025-06-12 08:55:00", 6 * i), "198.51.100.61", "10.0.0.7", 300 + (i * 67) % 600, "allowed" if i % 4 == 0 else "blocked", 3389, "TCP", "CN", "F2_rdp_bruteforce"])
# F3 - Exfiltration (T1041 / T1048): internal host uploads ~175 MB to one external IP over 443 in 3 min
for i in range(12):
    fw.append([ts("2025-06-12 09:00:00", 15 * i), "192.168.1.105", "198.51.100.200", 12_000_000 + (i * 1_234_567) % 6_000_000, "allowed", 443, "TCP", "NL", "F3_exfiltration"])

WH = ["timestamp", "client_ip", "method", "resource", "status_code", "bytes_sent", "user_agent", "scenario"]
FH = ["timestamp", "src_ip", "dest_ip", "bytes", "action", "port", "protocol", "country", "scenario"]
if __name__ == "__main__":
    for name, hdr, rows in [("sim_web_attacks.csv", WH, web), ("sim_fw_attacks.csv", FH, fw)]:
        with open(OUT / name, "w", newline="") as fh:
            w = csv.writer(fh, lineterminator="\n"); w.writerow(hdr); w.writerows(rows)
        print(f"{name}: {len(rows)} rows")
