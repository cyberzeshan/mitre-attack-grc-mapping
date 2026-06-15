# TA0006 — Credential Access: ATT&CK to GRC Control Mapping

**Tactic Description:** Techniques for stealing credentials like account names and passwords. Techniques used to obtain credentials include keylogging or credential dumping. Using legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts.

---

## T1003 — OS Credential Dumping

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1003.001 LSASS Memory | IA-5, SC-28, AC-6, AU-12 | A.5.17, A.8.5 | CIS 5.4, 13.1 | CC6.1 | 🔴 Critical |
| T1003.002 Security Account Manager (SAM) | IA-5, SC-28, AC-6 | A.5.17, A.8.5 | CIS 5.4 | CC6.1 | 🟠 High |
| T1003.003 NTDS | IA-5, SC-28, AC-3, AC-6 | A.5.17, A.8.5 | CIS 5.4, 13 | CC6.1 | 🟠 High |
| T1003.004 LSA Secrets | IA-5, SC-28 | A.5.17 | CIS 5.4 | CC6.1 | 🟠 High |
| T1003.006 DCSync | IA-5, AC-3, AC-6, AU-12 | A.5.17, A.5.18 | CIS 5.4, 6 | CC6.1, CC6.2 | 🟠 High |
| T1003.007 Proc Filesystem (Linux) | IA-5, AC-6 | A.5.17 | CIS 5.4 | CC6.1 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Windows Event Log 4656/4663 (LSASS handle), 4624 (suspicious logon type), Sysmon Event 10 (process access to lsass.exe), EDR credential access telemetry
- **Key Indicators:** `lsass.exe` accessed by non-Windows tools, `mimikatz`, `procdump`, or `comsvcs.dll` MiniDump in command line
- **Detection Rules:** EDR alert on `lsass.exe` memory reads by non-Microsoft processes; alert on DCSync replication from non-DC hosts

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1043 Credential Access Protection | IA-5, SC-28 | Enable Windows Credential Guard to protect LSASS in hypervisor-isolated environment |
| M1026 Privileged Account Management | AC-6 | PAM solution; restrict SeDebugPrivilege to minimal necessary accounts |
| M1028 Operating System Configuration | CM-6 | Enable Protected Process Light (PPL) for LSASS (`HKLM\SYSTEM\...\lsa\RunAsPPL = 1`) |
| M1027 Password Policies | IA-5 | Randomize LAPS passwords for local admin; rotate service account passwords |
| M1015 Active Directory Configuration | AC-3 | Implement tiered AD model; restrict DCSync rights (Replicating Directory Changes) |

---

## T1110 — Brute Force

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1110.001 Password Guessing | AC-7, IA-5, AU-6 | A.5.17, A.8.5 | CIS 5.2, 6.3 | CC6.1 | 🟡 Medium |
| T1110.002 Password Cracking | IA-5, SC-28 | A.5.17 | CIS 5.2 | CC6.1 | 🟡 Medium |
| T1110.003 Password Spraying | AC-7, IA-5, AU-6, SI-4 | A.5.17, A.8.5 | CIS 5.2, 6.3 | CC6.1 | 🟠 High |
| T1110.004 Credential Stuffing | AC-7, IA-5, AU-6 | A.5.17 | CIS 5.2, 5.3 | CC6.1 | 🟠 High |

### Detection Guidance
- **Data Sources:** Authentication failure logs (Windows Event 4625), Azure AD Sign-in logs, SIEM correlation rules, UEBA
- **Key Indicators:** >10 failed logons in 5 minutes from single source, low-and-slow failed attempts across many accounts (spraying pattern)
- **Detection Rules:** Account lockout storm detection, successful auth following multiple failures, geo-velocity impossible travel

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1036 Account Use Policies | AC-7 | Account lockout after 5 failed attempts; smart lockout in Azure AD |
| M1032 Multi-factor Authentication | IA-2 | MFA on all accounts; phishing-resistant MFA (FIDO2) for privileged accounts |
| M1027 Password Policies | IA-5 | 16+ character minimums; Have I Been Pwned integration for breach-compromised password detection |
| M1018 User Account Management | AC-2 | Disable unused accounts; limit external-facing account exposure |

---

## T1056 — Input Capture (Keylogging)

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1056.001 Keylogging | SI-3, SC-28, CM-7 | A.8.19, A.5.17 | CIS 10.1, 13 | CC7.2 | 🟡 Medium |
| T1056.002 GUI Input Capture | SI-3, CM-7 | A.8.19 | CIS 10.1 | CC7.2 | 🔵 Low |
| T1056.003 Web Portal Capture | SC-8, SC-28 | A.8.20, A.8.23 | CIS 9, 12 | CC6.1 | 🟡 Medium |
| T1056.004 Credential API Hooking | SI-3, CM-7 | A.8.19 | CIS 10.1 | CC7.2 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** EDR process/hook telemetry, API monitoring for `SetWindowsHookEx`, network flow analysis for data exfil
- **Key Indicators:** Processes hooking keyboard input APIs, unexpected DLLs loaded into browser processes

---

## T1555 — Credentials from Password Stores

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1555.003 Credentials from Web Browsers | IA-5, SC-28, CM-7 | A.5.17, A.8.5 | CIS 5.2, 10 | CC6.1 | 🟠 High |
| T1555.004 Windows Credential Manager | IA-5, SC-28 | A.5.17 | CIS 5.2 | CC6.1 | 🟡 Medium |
| T1555.005 Password Managers | IA-5, SC-28 | A.5.17 | CIS 5.1 | CC6.1 | 🟡 Medium |
| T1555.006 Cloud Secrets Management Stores | IA-5, SC-28, AC-3 | A.5.17, A.8.5 | CIS 5.5 | CC6.1 | 🟠 High |

### Detection Guidance
- **Data Sources:** EDR file access telemetry, browser credential store access alerts, cloud secrets manager audit logs
- **Key Indicators:** Processes accessing `%APPDATA%\Local\Google\Chrome\User Data\Default\Login Data` (Chrome credential DB), unexpected access to AWS Secrets Manager

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1054 Software Configuration | CM-6 | Disable browser password saving via GPO/MDM; enforce enterprise password manager |
| M1026 Privileged Account Management | AC-6 | Secrets rotation in cloud environments; no hardcoded credentials in code |
| M1043 Credential Access Protection | SC-28 | Encrypt credential stores at rest; enforce access logging on secrets managers |

---

## T1558 — Steal or Forge Kerberos Tickets

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1558.001 Golden Ticket | IA-5, SC-28, AC-3, AU-12 | A.5.17, A.5.18 | CIS 5.4, 6 | CC6.1, CC6.2 | 🟠 High |
| T1558.002 Silver Ticket | IA-5, SC-28 | A.5.17 | CIS 5.4 | CC6.1 | 🟠 High |
| T1558.003 Kerberoasting | IA-5, CM-6, AC-6 | A.5.17, A.8.5 | CIS 5.4 | CC6.1 | 🟠 High |
| T1558.004 AS-REP Roasting | IA-5, CM-6 | A.5.17 | CIS 5.2 | CC6.1 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Windows Event Log 4769 (Kerberos service ticket), 4768 (TGT request), domain controller logs
- **Key Indicators:** Kerberoasting: abnormal number of TGS requests for RC4-encrypted tickets; Golden Ticket: abnormal ticket lifetimes, ticket with non-standard PAC fields

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1026 Privileged Account Management | AC-6 | Use Managed Service Accounts (gMSA) for services; minimize SPNs on privileged accounts |
| M1027 Password Policies | IA-5 | 25+ char passwords for service accounts targeted by Kerberoasting |
| M1015 Active Directory Configuration | CM-6 | Enable AES-only Kerberos encryption; rotate KRBTGT password twice after suspected compromise |

---

## Coverage Summary — TA0006 Credential Access

| Control Domain | Coverage | Notes |
|:---|:---:|:---|
| NIST SP 800-53 | ●●●●● | IA-5, AC-6, AC-7, SC-28 provide excellent credential protection coverage |
| ISO 27001:2022 | ●●●○○ | A.5.17 covers credential management; lacks technical specificity for LSASS/Kerberos |
| CIS Controls v8 | ●●●●● | CIS 5 (account management), 6 (access control), 13 (data protection) strongly aligned |
| SOC 2 TSC | ●●●●○ | CC6.1 (logical access controls) covers well; detection controls less prescriptive |
