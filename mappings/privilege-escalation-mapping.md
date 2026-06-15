# TA0004 — Privilege Escalation: ATT&CK to GRC Control Mapping

**Tactic Description:** Techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives.

---

## T1055 — Process Injection

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1055.001 Dynamic-link Library Injection | SI-3, CM-7, SC-39 | A.8.8, A.8.19 | CIS 10.1, 13 | CC7.2 | 🟠 High |
| T1055.002 Portable Executable Injection | SI-3, CM-7, SC-39 | A.8.8, A.8.19 | CIS 10.1, 13 | CC7.2 | 🟠 High |
| T1055.003 Thread Execution Hijacking | SI-3, CM-7, SC-39 | A.8.8, A.8.19 | CIS 10.1 | CC7.2 | 🟠 High |
| T1055.004 Asynchronous Procedure Call | SI-3, CM-7 | A.8.8 | CIS 10.1 | CC7.2 | 🟡 Medium |
| T1055.012 Process Hollowing | SI-3, CM-7, SC-39 | A.8.8, A.8.19 | CIS 10.1 | CC7.2 | 🟠 High |

### Detection Guidance
- **Data Sources:** EDR process telemetry, Windows API call monitoring, memory analysis tools
- **Key Indicators:** Processes allocating memory in other process space (`VirtualAllocEx`, `WriteProcessMemory`), unusual parent-child process relationships
- **Detection Rules:** EDR behavioral rules for cross-process memory operations, alerts on `CreateRemoteThread` from unexpected callers

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1040 Behavior Prevention on Endpoint | SI-3, CM-7 | EDR with behavioral detection (CrowdStrike, SentinelOne) — block injection behaviors |
| M1026 Privileged Account Management | AC-6 | Least-privilege execution; standard users cannot debug or inject into system processes |
| M1048 Application Isolation and Sandboxing | SC-39 | Leverage Windows Credential Guard, Exploit Guard |
| M1019 Threat Intelligence Program | RA-3 | IOC feeds for known injection utilities |

---

## T1068 — Exploitation for Privilege Escalation

| Attribute | Details |
|:---|:---|
| Tactic | Privilege Escalation |
| Prevalence | 🟠 High |
| NIST SP 800-53 | RA-5, SI-2, CM-7, SC-39 |
| ISO 27001 | A.8.8 (Vulnerability Management), A.8.19 |
| CIS Controls v8 | CIS 7.4 (Remediation Timeliness), CIS 10.5 |
| SOC 2 TSC | CC7.1, CC7.2 |

### Detection Guidance
- **Data Sources:** EDR exploit detection, kernel telemetry, Windows Error Reporting (WER), crash dumps
- **Key Indicators:** Token manipulation API calls, privilege escalation chains in EDR alerts, unexpected SYSTEM-level child processes

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1051 Update Software | SI-2, RA-5 | 30-day SLA for critical privilege escalation CVEs |
| M1050 Exploit Protection | CM-7, SC-39 | Enable Windows Exploit Guard (EMET successor), DEP/ASLR |
| M1019 Threat Intelligence | RA-3 | Subscribe to Microsoft Patch Tuesday + CISA KEV feeds |

---

## T1548 — Abuse Elevation Control Mechanism

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1548.001 Setuid and Setgid (Linux) | AC-6, CM-6, CM-7 | A.8.18, A.8.19 | CIS 4.1 | CC6.1 | 🟡 Medium |
| T1548.002 Bypass User Account Control | CM-7, CM-6, AC-6 | A.8.19 | CIS 4.1, 5.4 | CC6.1 | 🟠 High |
| T1548.003 Sudo and Sudo Caching | AC-6, CM-6 | A.8.18 | CIS 4.1, 5.4 | CC6.1 | 🟡 Medium |
| T1548.004 Elevated Execution with Prompt | CM-6, CM-7 | A.8.19 | CIS 4.1 | CC6.1 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Windows Event Log 4688 (process creation with elevation), `sudo` logs, Sysmon
- **Key Indicators:** UAC bypass via `fodhelper.exe`, `eventvwr.exe`, or COM object hijacking; `sudo` commands from unusual users

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1047 Audit | AU-12 | Log all elevation events; alert on UAC bypass patterns |
| M1052 User Account Control | CM-6, CM-7 | Set UAC to maximum, disable auto-elevation for standard users |
| M1026 Privileged Account Management | AC-6 | Separate admin and user accounts; require re-authentication for elevation |

---

## T1134 — Access Token Manipulation

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1134.001 Token Impersonation/Theft | AC-6, SI-3, AU-12 | A.8.5, A.8.19 | CIS 5.4, 13 | CC6.1, CC7.2 | 🟠 High |
| T1134.002 Create Process with Token | AC-6, CM-7 | A.8.5, A.8.19 | CIS 5.4 | CC6.1 | 🟠 High |
| T1134.003 Make and Impersonate Token | AC-6, IA-5 | A.5.17, A.8.5 | CIS 5.4 | CC6.1 | 🟡 Medium |
| T1134.005 SID-History Injection | AC-2, AC-6, AU-12 | A.5.15, A.5.18 | CIS 5, 6 | CC6.1, CC6.2 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Windows Event Log 4624 (logon type 9), 4648, Sysmon, EDR telemetry
- **Key Indicators:** LogonType 9 (NewCredentials) from non-standard processes, `SeImpersonatePrivilege` abuse

---

## T1078 — Valid Accounts (Privilege Escalation context)

See [initial-access-mapping.md](initial-access-mapping.md) for full coverage. In the privilege escalation context:

- **NIST:** AC-6 (Least Privilege), AC-2 (Account Management), IA-5
- **ISO 27001:** A.5.15 (Access Control), A.5.18 (Privileged Access Rights)
- **CIS:** CIS 5.4 (Restrict Admin Privileges), CIS 6.2 (Access Reviews)
- **Detection:** Baseline admin account usage, alert on privileged actions from shared accounts

---

## Coverage Summary — TA0004 Privilege Escalation

| Control Domain | Coverage | Notes |
|:---|:---:|:---|
| NIST SP 800-53 | ●●●●○ | AC-6, SI-3, RA-5, SC-39 provide comprehensive coverage; CM-7 hardening critical |
| ISO 27001:2022 | ●●●○○ | A.8.8/8.19 are high-level; lacks kernel-level and memory protection controls |
| CIS Controls v8 | ●●●●● | CIS 5.4, 7.4, 10.1 directly map to privilege escalation mitigations |
| SOC 2 TSC | ●●●○○ | CC6.1 (logical access) and CC7.2 (anomaly detection) partially cover this tactic |
