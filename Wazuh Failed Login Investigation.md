# Case Study 01: Wzuh SOC Failed Login Investigation

## Data Notice

This case study is based on lab-generated security telemetry from an Wazuh SOC lab environment. No real company logs, customer data, or sensitive information are included.

## Scenario

A Wazuh Server was deployed on a Ubuntu Server and Wazuh agents are installed on Virtual systems. Windows Security Events were collected and forwarded into Log Analytics for investigation.

I investigate failed authentication activity using Wazuh, Log Analytics, Queries, Windows Security Event IDs, MITRE ATT&CK mapping, and  incident reporting.

---

## Alert Summary

| Field | Details |
|---|---|
| Alert Name | Multiple Failed Login Attempts Against Windows VM |
| Environment | Azure SOC Lab |
| Data Source | Windows Security Events |
| SIEM / Log Platform | WAZUH |
| Primary Event ID | 4625 |
| Severity | Medium |
| Initial Classification | Suspicious Activity |
| Final Classification | True Positive - Suspicious Authentication Activity |
| Affected Asset | Windows 10 VM |
| Asset IP | **192.168.6.20** |

---

## Investigation Objective

The objective of this investigation was to determine whether repeated failed login attempts against the  Windows VM represented normal background internet noise, brute-force behaviour, password spraying, or a potential credential attack requiring defensive action.

The investigation focused on:

- Identifying repeated failed logon attempts
- Understanding authentication patterns
- Validating the activity through centralized logs
- Mapping the behaviour to MITRE ATT&CK
- Recommending defensive controls

---

## Investigation
- Key Windows Event ID

### Event ID 4625 - Failed Login

Windows Security Event ID 4625 indicates that an account failed to log in successfully. In a SOC investigation, repeated 4625 events can indicate:

- Brute-force attempts
- Password spraying
- Credential stuffing
- Misconfigured services
- Unauthorized access attempts
- Internet scanning against exposed services

> Event ID 4625 was used as the main detection point for suspicious authentication activity.

---

## Queries Used

### Query 1: Review Failed Login Events

```
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, IpAddress, LoginType, Activity
| order by TimeGenerated desc
```

### Query 2: Failed Logins Over Time

```
SecurityEvent
| where EventID == 4625
| summarize FailedLogins = count() by bin(TimeGenerated, 1h)
| order by TimeGenerated asc
```
---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Credential Access | Brute Force | T1531 | Repeated failed login attempts observed through Event ID 4625 |
| Initial Access | Valid Accounts | T1078 | Attempted use of credentials against system |

---

## Evidence Reviewed

| Evidence Source | Event / Indicator | Analyst Finding |
|---|---|---|
| Windows Security Logs | Event ID 4625 | Failed login attempts observed against the Windows VM |
| Log Analytics | Authentication query results | Multiple failed logins were visible in centralized logs |

---

## Investigation Summary
The investigation identified failed login attempts against a Windows VM. Authentication logs were collected through Windows Security Events and reviewed in Log Analytics.

Event ID 4625 showed failed authentication attempts. The pattern was consistent with opportunistic scanning or brute-force activity.

#### **Classification:** True Positive - Suspicious Authentication Activity
The activity was classified as a true positive because failed login attempts were confirmed in Windows Security Events and were visible in centralized logging. Although no confirmed successful compromise was identified, the activity represented suspicious authentication behaviour against an internet-facing cloud asset.

This type of activity should be investigated because repeated failed logins can indicate brute-force attempts, password spraying, credential stuffing, or automated scanning.
No successful unauthorized login was confirmed in this case study. However, the repeated failed login activity was treated as suspicious and required hardening recommendations, including enforcing MFA where applicable, and improving detection logic.

---

## Business Impact Assessment

| Area | Assessment |
|---|---|
| Confidentiality | No confirmed data exposure |
| Integrity | No confirmed unauthorized changes |
| Availability | No service disruption confirmed |

---

## Recommended Response Actions

- Enforce MFA 
- Apply strong password and account lockout policies
- Monitor Event ID 4625 trends over time
- Review successful logons after repeated failures

---
 
## Recommended detection logic:

- Alert when one account receives failed login attempts
- Alerts when failed logins are followed by a successful login
- Alerts when administrative accounts receive failed login attempts
- Alert when failed logins occur outside expected access patterns

--- 

## Executive Summary

A SOC-style investigation was performed against failed authentication activity. Windows Security Event ID 4625 logs showed failed login attempts against a Windows VM. The activity was reviewed using Log Analytics to identify suspicious authentication patterns.

The investigation determined that the activity represented suspicious authentication behaviour consistent with opportunistic brute-force or scanning attempts. No confirmed successful compromise was identified, but the findings highlight the importance of restricting monitoring failed logins, enforcing MFA, and improving SIEM alerting for authentication anomalies.

---

