# Review: IBM assessment "Web Security Monitoring Using Splunk"

Reviewed 30 Sep 2026 against the original dataset (`sample-data/complex_log.csv`, 1,000 events, 10 Jun 2025). The improved version lives in this repo as the **Web App Threat Monitor v2** dashboard, detections D005–D008 and `alerts/savedsearches.conf`.

## Worth keeping

| Element | Why |
|---|---|
| Dashboard + scheduled report + alert | Covers the three core Splunk workflows (search/visualise, report, alert). This is the right skeleton. |
| `bin _time span=5m \| stats count \| where count > N` with a `*/5` cron | Correct shape for a rate-spike alert: the window matches the schedule. |
| Global time picker, readable SPL, no `index=*` | Good habits. |

## What to improve, with evidence

| # | Issue in the original | Evidence from the data | Fix in v2 |
|---|---|---|---|
| 1 | Alert threshold ">20 404s in 5 min" was never validated | Busiest 5-min window in the data has **4** 404s (p99 = 3). The alert could never fire. | Baseline first, then set the threshold with headroom (20 = 5× the max). Proven to fire on the W2 scan (91 in 5 min) and stay silent otherwise. |
| 2 | Daily report `timechart span=1d` over a one-day dataset | Produces a single bar. | Hourly **error rate %** by class (`Report - Daily web error rate`). |
| 3 | Panels count things instead of answering security questions | "Top IPs" = 24 IPs, all 35–49 requests, no outlier, and the write-up doesn't say so. | Panels for detections fired, scripted vs browser clients, `/admin` access by method/status, top 404 clients with distinct paths. |
| 4 | `source="complex_log.csv"` with no index or sourcetype | Fragile: breaks when the file is re-uploaded under another name. | `index=web_lab sourcetype=web:access`. |
| 5 | Alert had no throttling or severity, and was private | Would email once per window during a long scan. | Per-entity suppression, severity 1–5, `alert.track=1`, dashboards shared app-wide. |
| 6 | No findings, interpretation, MITRE mapping or conclusion | The PDF is screenshots only, and "Click for link" points at a private trial instance. | `docs/lab-detection-results.md` with a detection matrix, findings and caveats. MITRE IDs in every detection. |
| 7 | Screenshots are dark, low-resolution and cropped | Hard to read in a PDF. | Light theme, one screenshot per section, panel titles that state the question. |

## One-line summary for an interviewer

> The first version showed I could build panels. The second shows I can baseline data, set defensible thresholds, prove detections fire with zero false positives, and report findings, including when the honest finding is "the data has no attack in it".
