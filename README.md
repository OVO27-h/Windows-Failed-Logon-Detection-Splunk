# Windows Failed-Logon Detection and Alerting Using Splunk SIEM

## Project overview
This hands-on SOC lab demonstrates the investigation of repeated Windows authentication failures, correlation with a subsequent successful logon, development of a threshold-based Splunk detection, and validation of a scheduled alert. **All authentication activity was generated in a controlled lab environment**; this is not a report of a real compromise.

## Objectives
- Investigate failed Windows sign-in events (Event ID **4625**) and correlate related successful sign-ins (Event ID **4624**).
- Build an SPL search to identify accounts with **five or more failures per fixed five-minute time bucket**.
- Configure and validate a scheduled Splunk alert using a separate controlled test.
- Document the evidence and explain the analyst's interpretation.

## Lab environment
| Component | Details |
|---|---|
| SIEM | Splunk Enterprise |
| Data source | Windows Security Event Logs (`sourcetype="WinEventLog:Security"`, `index=main`) |
| Endpoint | `DESKTOP-PD8H8GJ` |
| Test account | `DELL` |
| Relevant event IDs | 4625 (failed logon), 4624 (successful logon) |
| Date | 7 October 2026 |

## Investigation workflow
1. Reviewed repeated Event ID 4625 records and their frequency.
2. Examined the affected account, logon type, authentication metadata, failure codes, and source address.
3. Correlated the failed logons with a subsequent Event ID 4624 success for the same account and endpoint.
4. Developed and refined an SPL threshold search, excluding machine accounts ending in `$`.
5. Configured a scheduled alert and tested it with a new sequence of controlled failed sign-ins.
6. Verified that the alert triggered and recorded the results.

## Key findings
| Finding | Evidence and interpretation |
|---|---|
| Initial failure burst | **5 failures** from **13:15:32.436–13:15:46.403**, approximately 14 seconds |
| Authentication details | Account `DELL`; interactive logon (type 2); source `127.0.0.1`; host `DESKTOP-PD8H8GJ`; bad-password substatus `0xC000006A` |
| Successful sign-in correlation | Event ID **4624** at **13:15:50.765**, about four seconds after the last failure, sharing account and endpoint context |
| Detection | SPL identified **≥5 failures in a fixed five-minute bucket** for an account and host |
| Alert validation | **6 new failures** from **16:20:33.838–16:20:46.114**; the medium-severity **“Repeated Failed Logon Attempts – Windows”** alert triggered around **16:25** |

**Analyst assessment:** In a real SOC, failures followed by success would warrant investigation for possible credential guessing. Here, the events were intentionally generated. The loopback address `127.0.0.1` indicates a local source, not a remote attacker. The alert demonstrates detection of the configured pattern; it does not establish malicious intent.

## Detection logic
The tested SPL search is stored in [`Detection/failed-logon-detection.spl`](Detection/failed-logon-detection.spl).

The search filters for Event ID 4625, groups records by account and computer in **fixed five-minute buckets**, counts failures, excludes machine accounts ending in `$`, and returns relevant triage fields. The fixed buckets are **not a sliding five-minute window**; activity split across a bucket boundary may not reach the threshold in either bucket.

## Evidence
- [Initial failed-logon summary](Screenshots/01-failed-logon-summary.png)
- [Refined detection search](Screenshots/05-splunk-refined-brute-force-detection-search.png)
- [Triggered alert](Screenshots/08-splunk-triggered-failed-logon-alert.png)
- [Alert search results](Screenshots/09-splunk-triggered-alert-results.png)

Additional evidence and detailed observations are recorded in [`Documentation/investigation-findings.txt`](Documentation/investigation-findings.txt) and the [`SOC investigation report`](Documentation/incident-report.md).

> **Repository check:** Ensure your uploaded screenshots and findings file use these exact names, or update the links to match your filenames.

## Security recommendations
For a real-world occurrence of this pattern, an analyst should verify whether the attempts were expected, review related authentication events and endpoint activity, check for account compromise indicators, and follow the organization's incident response and account-protection procedures. Consider tuning alert thresholds and time-window behavior to reduce false positives and missed detections.

## Skills demonstrated
Windows Security Event analysis · Splunk SPL · SIEM alert configuration · Authentication event correlation · Detection validation · SOC investigation documentation

## Project status
**Completed lab investigation and successful scheduled-alert validation.**
