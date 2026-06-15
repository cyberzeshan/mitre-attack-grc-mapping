# TA0003 — Persistence: ATT&CK to GRC Control Mapping

**Tactic Description:** Techniques used to maintain access to systems across restarts, changed credentials, and other interruptions. Adversaries use persistence to ensure they can continue operations even if their initial foothold is removed.

---

## T1053 — Scheduled Task/Job

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1053.002 At | CM-7, AU-12, AC-6 | A.8.19, A.8.15 | CIS 4.1, 8.2 | CC7.2 | 🟡 Medium |
| T1053.003 Cron | CM-7, AU-12, AC-6 | A.8.19, A.8.15 | CIS 4.1, 8.2 | CC7.2 | 🟡 Medium |
| T1053.005 Scheduled Task (Windows) | CM-7, AU-12, SI-7 | A.8.19, A.8.15 | CIS 4.1, 8.2 | CC6.1, CC7.2 | 🟡 Medium |
| T1053.006 Systemd Timers | CM-7, AU-12 | A.8.19 | CIS 4.1 | CC7.2 | 🔵 Low |
| T1053.007 Container Orchestration Job | CM-7, SC-39 | A.8.19, A.8.25 | CIS 4.1 | CC7.2 | 🔵 Low |

### Detection Guidance
- **Data Sources:** Windows Event Log 4698 (task created), 4702 (task updated), 4699 (task deleted), Sysmon Event 11/13
- **Key Indicators:** Tasks created by non-admin users, tasks with encoded PowerShell commands, tasks pointing to temp directories
- **Detection Rules:** Alert on scheduled task creation outside change windows, tasks invoking scripting interpreters

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1026 Privileged Account Management | AC-6 | Restrict task creation to administrators; log all changes |
| M1047 Audit | AU-12, CM-7 | Enable advanced audit policy for task creation/modification events |
| M1028 Operating System Configuration | CM-6, CM-7 | Restrict `schtasks` and `at` to privileged groups via GPO |

---

## T1547 — Boot or Logon Autostart Execution

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1547.001 Registry Run Keys | CM-7, SI-7, AU-12 | A.8.19, A.8.15 | CIS 2.7, 4.1 | CC7.2 | 🟠 High |
| T1547.004 Winlogon Helper DLL | CM-7, SI-7 | A.8.19 | CIS 2.7 | CC7.2 | 🟡 Medium |
| T1547.009 Shortcut Modification | CM-7, AU-12 | A.8.15 | CIS 8.2 | CC7.2 | 🟡 Medium |
| T1547.014 Active Directory Shadow Credentials | IA-5, AC-2, AU-12 | A.5.16, A.8.5 | CIS 5, 6 | CC6.1, CC6.2 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Registry monitoring (Sysmon Event 12/13/14), EDR process/file telemetry, Windows Event Log
- **Key Indicators:** Modifications to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, new DLLs in system directories

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1024 Restrict Registry Permissions | CM-7, SI-7 | Restrict write access to autorun registry keys via GPO |
| M1022 Restrict File and Directory Permissions | CM-6 | Lock down startup folders and system directories |
| M1026 Privileged Account Management | AC-6 | Only SYSTEM/admin accounts can modify autostart locations |

---

## T1136 — Create Account

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1136.001 Local Account | AC-2, AU-9, IA-2 | A.5.16, A.5.18 | CIS 5.2, 6 | CC6.2 | 🟡 Medium |
| T1136.002 Domain Account | AC-2, AU-9, IA-2 | A.5.16, A.5.18 | CIS 5.2, 6 | CC6.2 | 🟡 Medium |
| T1136.003 Cloud Account | AC-2, AU-9, IA-2 | A.5.16, A.5.18 | CIS 5.5, 12.8 | CC6.2 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Windows Event Log 4720 (account created), 4728/4732 (group membership changes), Azure AD audit logs
- **Key Indicators:** New accounts created outside provisioning workflow, accounts added to privileged groups without ticket

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1032 Multi-factor Authentication | IA-2 | MFA on all account creation workflows |
| M1026 Privileged Account Management | AC-2, AC-6 | Provisioning workflow enforced via IGA tool (e.g., SailPoint, Saviynt) |
| M1047 Audit | AU-9, AU-12 | Alert SIEM on account creation events outside approved provisioning systems |

---

## T1098 — Account Manipulation

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1098.001 Additional Cloud Credentials | AC-2, IA-5, AU-12 | A.5.16, A.5.18 | CIS 5.5 | CC6.1, CC6.2 | 🟠 High |
| T1098.002 Additional Email Delegate Permissions | AC-2, AU-12 | A.5.16, A.5.18 | CIS 6 | CC6.2 | 🟡 Medium |
| T1098.003 Additional Cloud Roles | AC-2, AC-3, AU-12 | A.5.15, A.5.18 | CIS 5.5, 6 | CC6.2 | 🟠 High |
| T1098.005 Registered Service Principal | AC-2, IA-5, AU-12 | A.5.16, A.5.18 | CIS 5.5 | CC6.1 | 🟠 High |

### Detection Guidance
- **Data Sources:** Azure AD audit logs, AWS CloudTrail, Google Workspace audit, IAM permission change events
- **Key Indicators:** New API keys attached to existing service accounts, role escalations, added federated identity providers

---

## T1543 — Create or Modify System Process

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1543.003 Windows Service | CM-7, SI-7, AU-12 | A.8.19, A.8.15 | CIS 4.1, 8.2 | CC7.2 | 🟠 High |
| T1543.004 Launch Daemon (macOS) | CM-7, SI-7 | A.8.19 | CIS 4.1 | CC7.2 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Windows Event Log 7045 (new service), 4697, Sysmon, EDR service creation telemetry
- **Key Indicators:** Services created with non-standard binary paths, services running from temp directories, service account changes

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1022 Restrict File and Directory Permissions | CM-6 | Restrict service installation to privileged accounts |
| M1024 Restrict Registry Permissions | CM-7 | Lock HKLM\SYSTEM\CurrentControlSet\Services |
| M1045 Code Signing | SI-7 | Require signed service binaries |

---

## Coverage Summary — TA0003 Persistence

| Control Domain | Coverage | Notes |
|:---|:---:|:---|
| NIST SP 800-53 | ●●●●○ | AU-12, CM-7, AC-2 provide strong detection and prevention anchors |
| ISO 27001:2022 | ●●●○○ | A.8.19 covers configuration hardening; lacks detection-specific controls |
| CIS Controls v8 | ●●●●● | CIS 4 (config), 5 (accounts), 8 (audit logs) directly address all sub-techniques |
| SOC 2 TSC | ●●○○○ | CC6.1/CC7.2 provide minimal coverage; no technical persistence detection controls |
