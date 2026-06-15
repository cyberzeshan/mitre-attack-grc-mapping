# TA0005 — Defense Evasion: ATT&CK to GRC Control Mapping

**Tactic Description:** Techniques adversaries use to avoid detection throughout their compromise. Includes disabling security software, obfuscating/encrypting data and scripts, and abusing trusted processes to blend into legitimate activity.

---

## T1562 — Impair Defenses

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1562.001 Disable or Modify Tools | AU-9, CM-7, SI-3 | A.8.19, A.8.15 | CIS 10.1, 10.2 | CC7.2 | 🟠 High |
| T1562.002 Disable Windows Event Logging | AU-9, AU-12, CM-7 | A.8.15, A.8.19 | CIS 8.2, 8.3 | CC7.2 | 🟠 High |
| T1562.004 Disable or Modify System Firewall | CM-7, SC-7, AU-9 | A.8.19, A.8.20 | CIS 4.5, 12.2 | CC7.2 | 🟠 High |
| T1562.006 Indicator Blocking | AU-9, SI-4 | A.8.15 | CIS 8.5 | CC7.2 | 🟡 Medium |
| T1562.010 Downgrade Attack | CM-7, SC-8 | A.8.19, A.8.20 | CIS 4.1 | CC7.2 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Security tool health monitoring, Windows Event Log 7036 (service state change), WMI subscription alerts, EDR self-protection telemetry
- **Key Indicators:** AV/EDR process termination, event log service disabled (7036), audit policy changes (4719)
- **Detection Rules:** Alert on security tool failures/stops, audit policy modification (Windows Event 4719), firewall state changes

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1022 Restrict File and Directory Permissions | AU-9, CM-7 | Protect security tool binaries/configs with SYSTEM-only write permissions |
| M1024 Restrict Registry Permissions | AU-9 | Lock security tool registry keys via GPO |
| M1054 Software Configuration | CM-6 | Enable tamper protection in EDR/AV; remote management only |
| M1047 Audit | AU-12 | Forward logs to immutable SIEM before local manipulation possible |

---

## T1070 — Indicator Removal

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1070.001 Clear Windows Event Logs | AU-9, AU-12, SI-7 | A.8.15 | CIS 8.2, 8.9 | CC7.2 | 🟠 High |
| T1070.002 Clear Linux or Mac System Logs | AU-9, AU-12 | A.8.15 | CIS 8.2 | CC7.2 | 🟡 Medium |
| T1070.003 Clear Command History | AU-9, AU-12 | A.8.15 | CIS 8.2 | CC7.2 | 🟡 Medium |
| T1070.004 File Deletion | AU-9, SI-7 | A.8.15 | CIS 8.2 | CC7.2 | 🟡 Medium |
| T1070.006 Timestomp | AU-9, SI-7 | A.8.15 | CIS 8.9 | CC7.2 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Windows Event Log 1102 (log cleared), 104, Sysmon Event 23/26, centralized log management
- **Key Indicators:** Event log cleared (1102), gaps in log timeline, file metadata inconsistencies
- **Detection Rules:** Alert on Event ID 1102 from non-admin, log collection gaps > 5 minutes

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1029 Remote Data Storage | AU-9 | Forward all logs to centralized, tamper-resistant SIEM (Splunk, Microsoft Sentinel) |
| M1047 Audit | AU-12 | Log clearing itself is logged and forwarded before data is lost |
| M1022 Restrict File and Directory Permissions | AU-9 | Restrict log clearing to specific admin roles with dual approval |

---

## T1027 — Obfuscated Files or Information

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1027.001 Binary Padding | SI-3, CM-7 | A.8.19 | CIS 10.1 | CC7.2 | 🟡 Medium |
| T1027.002 Software Packing | SI-3, CM-7 | A.8.19 | CIS 10.1 | CC7.2 | 🟡 Medium |
| T1027.004 Compile After Delivery | SI-3, CM-7, CM-14 | A.8.19, A.8.25 | CIS 2.7, 10.1 | CC7.2 | 🟡 Medium |
| T1027.009 Embedded Payloads | SI-3, CM-7 | A.8.19 | CIS 10.1 | CC7.2 | 🟡 Medium |
| T1027.010 Command Obfuscation | SI-3, AU-12 | A.8.15, A.8.19 | CIS 8.2, 10.1 | CC7.2 | 🟠 High |

### Detection Guidance
- **Data Sources:** Script block logging (PowerShell Event 4104), EDR with AMSI integration, sandboxed execution
- **Key Indicators:** Base64-encoded PowerShell commands, high entropy scripts, `Invoke-Expression` with embedded strings
- **Detection Rules:** AMSI-based detection of obfuscated script execution, entropy analysis on executed scripts

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1049 Antivirus/Antimalware | SI-3 | AMSI-enabled AV/EDR that unpacks obfuscation before detection |
| M1042 Disable or Remove Feature/Program | CM-7 | Constrained Language Mode for PowerShell; block `wscript`/`cscript` for standard users |
| M1040 Behavior Prevention | SI-3 | EDR behavioral rules targeting obfuscation indicators |

---

## T1036 — Masquerading

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1036.001 Invalid Code Signature | SI-7, CM-14 | A.8.25 | CIS 2.7 | CC7.2 | 🟡 Medium |
| T1036.003 Rename System Utilities | CM-7, SI-7 | A.8.19 | CIS 2.7, 4.1 | CC7.2 | 🟡 Medium |
| T1036.004 Masquerade Task or Service | CM-7, SI-7 | A.8.19 | CIS 4.1 | CC7.2 | 🟡 Medium |
| T1036.005 Match Legitimate Name or Location | CM-7, SI-7, AU-12 | A.8.19 | CIS 2.7, 8.2 | CC7.2 | 🟠 High |

### Detection Guidance
- **Data Sources:** Code signing validation, file hash comparison against known-good baseline, Sysmon process creation (Event 1)
- **Key Indicators:** `svchost.exe` running from non-`system32` path, unsigned binaries with system-matching names

---

## T1218 — System Binary Proxy Execution (LOLBins)

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1218.001 Compiled HTML File | CM-7, SI-3 | A.8.19 | CIS 2.7 | CC7.2 | 🟡 Medium |
| T1218.003 CMSTP | CM-7, SI-3 | A.8.19 | CIS 2.7 | CC7.2 | 🟡 Medium |
| T1218.005 Mshta | CM-7, SI-3 | A.8.19 | CIS 2.7 | CC7.2 | 🟠 High |
| T1218.007 Msiexec | CM-7, SI-3 | A.8.19 | CIS 2.7 | CC7.2 | 🟡 Medium |
| T1218.010 Regsvr32 | CM-7, SI-3 | A.8.19 | CIS 2.7 | CC7.2 | 🟠 High |
| T1218.011 Rundll32 | CM-7, SI-3 | A.8.19 | CIS 2.7 | CC7.2 | 🟠 High |

### Detection Guidance
- **Data Sources:** Sysmon process creation, EDR telemetry, command-line argument logging
- **Key Indicators:** `mshta.exe` loading remote scripts, `regsvr32` with `/s /u` loading COM objects from the internet, `rundll32` with unusual DLL paths

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1038 Execution Prevention | CM-7 | Application allowlisting (WDAC/AppLocker) to block LOLBin misuse |
| M1026 Privileged Account Management | AC-6 | Standard user context prevents most LOLBin execution paths |
| M1042 Disable or Remove Feature | CM-7 | Disable `mshta.exe`, `wscript.exe`, `cscript.exe` via AppLocker for standard users |

---

## Coverage Summary — TA0005 Defense Evasion

| Control Domain | Coverage | Notes |
|:---|:---:|:---|
| NIST SP 800-53 | ●●●○○ | AU-9/12 cover log protection; SI-3/CM-7 cover tool hardening — but behavioral evasion hard to prescribe |
| ISO 27001:2022 | ●●○○○ | A.8.15/8.19 are present but far too high-level for evasion-specific controls |
| CIS Controls v8 | ●●●●○ | CIS 8 (audit logs), 10 (malware defenses), 2.7 (allowlisting) address most techniques |
| SOC 2 TSC | ●●○○○ | CC7.2 partially addresses anomaly detection; evasion techniques largely outside TSC scope |
