# TA0040 — Impact: ATT&CK to GRC Control Mapping

**Tactic Description:** Techniques adversaries use to disrupt availability or compromise integrity by manipulating business and operational processes. Adversaries may use this to achieve their end goal or provide cover for a breach of confidentiality.

---

## T1486 — Data Encrypted for Impact (Ransomware)

| Attribute | Details |
|:---|:---|
| Tactic | Impact |
| Prevalence | 🔴 Critical |
| NIST SP 800-53 | CP-9, CP-10, SC-28, IR-4, IR-6, SI-3 |
| ISO 27001 | A.5.29 (Business Continuity), A.8.13 (Data Backup), A.5.24–5.30 |
| CIS Controls v8 | CIS 11 (Data Recovery), CIS 17 (Incident Response), CIS 10 |
| SOC 2 TSC | CC7.5, A1.2, A1.3 |

### Detection Guidance
- **Data Sources:** File system monitoring (rapid file rename/encryption events), EDR behavioral detection, backup integrity monitoring, endpoint telemetry
- **Key Indicators:** Mass file rename operations (adding `.locked`, `.encrypted` extensions), shadow copy deletion (`vssadmin delete shadows`), volume shadow copy deletion via WMI, encryption of mapped network drives
- **Detection Rules:** Alert on >100 file modifications in 60 seconds from single process; alert on `vssadmin delete shadows /all` or equivalent WMI calls; EDR behavioral ransomware detection

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1053 Data Backup | CP-9, CP-10 | Immutable, air-gapped/offline backups; tested recovery; 3-2-1 rule + offsite |
| M1040 Behavior Prevention | SI-3 | EDR anti-ransomware module with behavioral canary file detection |
| M1049 Antivirus/Antimalware | SI-3 | Real-time AV with ransomware-specific signatures and heuristics |
| M1038 Execution Prevention | CM-7 | Application allowlisting to prevent unknown executables from running |
| M1026 Privileged Account Management | AC-6 | Least privilege: standard users cannot delete shadow copies or stop services |
| M1030 Network Segmentation | SC-7 | Limit network share access; ransomware spread confined to compromised segments |

---

## T1485 — Data Destruction

| Attribute | Details |
|:---|:---|
| Tactic | Impact |
| Prevalence | 🟡 Medium |
| NIST SP 800-53 | CP-9, SI-12, MP-6, IR-4 |
| ISO 27001 | A.8.13 (Data Backup), A.7.10 (Storage Media) |
| CIS Controls v8 | CIS 11.2, 11.4, 17 |
| SOC 2 TSC | A1.2, CC7.5 |

### Detection Guidance
- **Data Sources:** File system audit logs, database transaction logs, EDR file deletion telemetry, backup verification
- **Key Indicators:** Bulk file deletion, database DROP operations, overwrite tools (`sdelete`, `wipe`), AWS S3 bucket policy changes allowing deletion

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1053 Data Backup | CP-9 | Versioned, immutable backups prevent permanent data loss |
| M1022 Restrict File and Directory Permissions | CM-6 | Least privilege on data stores; no bulk-delete permissions for standard users |
| M1047 Audit | AU-9, AU-12 | Real-time alerting on mass deletion events |

---

## T1499 — Endpoint Denial of Service

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1499.001 OS Exhaustion Flood | SC-5, IR-4, CP-2 | A.5.29, A.8.6 | CIS 17 | A1.1 | 🟡 Medium |
| T1499.002 Service Exhaustion Flood | SC-5, IR-4 | A.5.29, A.8.6 | CIS 17 | A1.1 | 🟡 Medium |
| T1499.003 Application Exhaustion Flood | SC-5, RA-5, IR-4 | A.5.29, A.8.6 | CIS 7, 17 | A1.1 | 🟡 Medium |
| T1499.004 Application or System Exploitation | RA-5, SI-2, SC-5 | A.8.8, A.5.29 | CIS 7, 17 | A1.1, CC7.1 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** System resource monitoring, application performance monitoring (APM), network flow analysis
- **Key Indicators:** CPU/memory exhaustion by specific processes, connection count spikes, application error rates

---

## T1490 — Inhibit System Recovery

| Attribute | Details |
|:---|:---|
| Tactic | Impact |
| Prevalence | 🟠 High |
| NIST SP 800-53 | CP-9, CP-10, CM-7, IR-4 |
| ISO 27001 | A.8.13, A.5.29 |
| CIS Controls v8 | CIS 11.3, 11.5 |
| SOC 2 TSC | A1.2, CC7.5 |

### Detection Guidance
- **Data Sources:** Windows Event Log (VSS deletion events), EDR telemetry, backup system alerts
- **Key Indicators:** `vssadmin delete shadows`, `bcdedit /set recoveryenabled no`, WMIC shadowcopy delete, registry changes to disable safe mode recovery

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1053 Data Backup | CP-9 | Offsite immutable backups that cannot be deleted by endpoint access |
| M1026 Privileged Account Management | AC-6 | Restrict `vssadmin` to backup service accounts only |
| M1047 Audit | AU-12 | Alert on shadow copy deletion commands immediately |

---

## T1491 — Defacement

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1491.001 Internal Defacement | SI-7, CM-7, IR-4 | A.8.19, A.5.24 | CIS 17 | CC7.5 | 🔵 Low |
| T1491.002 External Defacement | SI-7, SC-7, RA-5, IR-4 | A.8.8, A.8.25, A.5.24 | CIS 7, 17 | CC7.5 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Web application monitoring, file integrity monitoring (FIM), CDN/WAF anomaly detection
- **Key Indicators:** Unexpected modification of web-accessible files, CDN purge events outside deployment windows

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1022 Restrict File and Directory Permissions | CM-6 | Web server files writable only by deployment service account |
| M1051 Update Software | SI-2, RA-5 | CMS and web framework patches on 30-day SLA |
| M1047 Audit | SI-7 | File integrity monitoring (FIM) on web root with alerting on unauthorized changes |

---

## T1561 — Disk Wipe

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1561.001 Disk Content Wipe | CP-9, MP-6, IR-4 | A.8.13, A.7.10, A.5.29 | CIS 11, 17 | A1.2 | 🟡 Medium |
| T1561.002 Disk Structure Wipe (MBR/VBR) | CP-9, IR-4 | A.8.13, A.5.29 | CIS 11, 17 | A1.2 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** EDR disk I/O monitoring, kernel driver alerts, raw disk access telemetry
- **Key Indicators:** Tools like `wiper`, raw disk handle requests outside OS disk management, simultaneous boot record modifications

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1053 Data Backup | CP-9 | Regular, tested, immutable backups enable recovery from disk wipe |
| M1022 Restrict File and Directory Permissions | AC-6 | Restrict raw disk access; only OS components should access MBR |
| M1038 Execution Prevention | CM-7 | Application allowlisting blocks unauthorized disk management tools |

---

## Ransomware-Specific Control Coverage

```
KILL-CHAIN STAGE        TECHNIQUE          PRIMARY CONTROLS
─────────────────────────────────────────────────────────────────────────
Pre-Encryption          T1486 (lead-up)    MFA (IA-2), EDR (SI-3), Least Priv (AC-6)
Shadow Copy Deletion    T1490              VSS monitoring (AU-12), Privileged access (AC-6)
File Encryption         T1486              EDR behavioral (SI-3), Canary files, Allowlist (CM-7)
Backup Targeting        T1490              Immutable backups (CP-9), Air-gap (CP-10)
Recovery               T1486 aftermath     Tested IR plan (IR-4), RTO/RPO-aligned backups (CP-9)
─────────────────────────────────────────────────────────────────────────
```

---

## Coverage Summary — TA0040 Impact

| Control Domain | Coverage | Notes |
|:---|:---:|:---|
| NIST SP 800-53 | ●●●●● | CP-9/10 (backup/recovery), IR-4 (incident response), SC-28 provide comprehensive coverage |
| ISO 27001:2022 | ●●●●○ | A.5.29 (business continuity) and A.8.13 (backups) are well-aligned; IR controls strong |
| CIS Controls v8 | ●●●●● | CIS 11 (data recovery), CIS 17 (incident response) directly address all impact techniques |
| SOC 2 TSC | ●●●●○ | A1.2 (recovery commitments), CC7.5 (incident response) provide strong coverage |
