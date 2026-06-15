# TA0001 — Initial Access: ATT&CK to GRC Control Mapping

**Tactic Description:** Techniques used to gain an initial foothold within a network. Adversaries use a variety of entry vectors to gain their initial access.

---

## T1566 — Phishing

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1566.001 Spearphishing Attachment | SI-8, AT-2, SC-7, SC-44 | A.6.3, A.8.23, A.5.14 | CIS 9.2, 9.4, 14.2 | CC6.1, CC2.2 | 🔴 Critical |
| T1566.002 Spearphishing Link | SI-8, SC-7, AT-2 | A.6.3, A.8.23 | CIS 9.3, 14 | CC6.1, CC2.2 | 🔴 Critical |
| T1566.003 Spearphishing via Service | SI-8, SC-7 | A.6.3, A.8.23 | CIS 9, 14 | CC6.1 | 🟠 High |
| T1566.004 Spearphishing Voice | AT-2, AT-3, SI-8 | A.6.3, A.5.14 | CIS 14.2 | CC2.2 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Email gateway logs, proxy/web filter logs, endpoint process telemetry, sandbox detonation reports
- **Key Indicators:** Executable attachments (.doc/.xls with macros), links to newly registered domains, mismatched sender domains
- **Detection Rules:** Alert on macro-enabled Office documents from external senders, block execution of attachments from temp directories

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1049 Antivirus/Antimalware | SI-3, SI-8 | Deploy email gateway with sandbox detonation (CIS 9.4) |
| M1031 Network Intrusion Prevention | SC-7, SI-4 | Implement email filtering with attachment sandboxing |
| M1017 User Training | AT-2, AT-3 | Quarterly phishing simulation + awareness training (CIS 14.2) |
| M1054 Software Configuration | CM-7, SC-7 | Block macro execution in Office suite, disable legacy email protocols |

---

## T1190 — Exploit Public-Facing Application

| Attribute | Details |
|:---|:---|
| Tactic | Initial Access |
| Prevalence | 🟠 High |
| NIST SP 800-53 | RA-5, SI-2, CM-7, SI-3, SC-7 |
| ISO 27001 | A.8.8 (Vulnerability Management), A.8.25 (Secure Development) |
| CIS Controls v8 | CIS 7.1 (Vulnerability Scanning), CIS 7.4 (Remediation Timeliness) |
| SOC 2 TSC | CC7.1, CC7.2 |

### Detection Guidance
- **Data Sources:** WAF logs, IDS/IPS alerts, web server access logs, vulnerability scanner outputs
- **Key Indicators:** Unusual HTTP methods (PUT, DELETE), oversized payloads, SQLi/XSS patterns in logs
- **Detection Rules:** WAF rule violations, CVE-based IDS signatures, anomalous server-side errors (500s)

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1048 Application Isolation | SC-7, SC-39 | WAF deployment, DMZ architecture |
| M1026 Privileged Account Management | AC-6 | Least-privilege app service accounts |
| M1016 Vulnerability Scanning | RA-5, SI-2 | Monthly external attack surface scans + 30-day critical patch SLA |
| M1051 Update Software | SI-2, CM-7 | Automated patching pipeline with verified deployment tracking |

---

## T1078 — Valid Accounts

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1078.001 Default Accounts | AC-2, CM-6, IA-5 | A.5.16, A.8.5 | CIS 5.1, 5.2 | CC6.1, CC6.2 | 🟠 High |
| T1078.002 Domain Accounts | AC-2, AC-3, IA-5, AU-12 | A.5.15, A.5.18 | CIS 5.3, 6.2 | CC6.1, CC6.2 | 🔴 Critical |
| T1078.003 Local Accounts | AC-2, AC-6, CM-6 | A.5.16, A.8.5 | CIS 5.4 | CC6.2 | 🟠 High |
| T1078.004 Cloud Accounts | AC-2, IA-5, SC-28 | A.5.15, A.5.18 | CIS 5.5, 12.8 | CC6.1, CC6.6 | 🟠 High |

### Detection Guidance
- **Data Sources:** Authentication logs (Windows Event 4624/4648), SIEM, UEBA, IAM audit logs
- **Key Indicators:** Logins from unusual geos, off-hours access, dormant account activity, concurrent sessions
- **Detection Rules:** Failed login spikes followed by success, access from new IP addresses, privileged account usage anomalies

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1032 Multi-factor Authentication | IA-2, IA-5 | Enforce MFA on all remote access and privileged accounts (CIS 5.3) |
| M1027 Password Policies | IA-5 | 16+ char minimum, no reuse, breach-notification-integrated screening |
| M1026 Privileged Account Management | AC-6, AC-17 | PAM solution, just-in-time access, privileged workstations |
| M1036 Account Use Policies | AC-2, AU-6 | Review dormant accounts monthly, auto-disable after 90 days |

---

## T1195 — Supply Chain Compromise

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1195.001 Compromise Software Dependencies | SR-3, SR-4, SI-7 | A.5.19, A.5.20, A.8.30 | CIS 2.5, 16.2 | CC9.2 | 🟠 High |
| T1195.002 Compromise Software Supply Chain | SR-3, SR-4, SI-7, CM-14 | A.5.19, A.5.20 | CIS 2.5 | CC9.2 | 🟠 High |
| T1195.003 Compromise Hardware Supply Chain | SR-3, SR-5, SA-19 | A.5.19, A.5.20 | CIS 1.1 | CC9.2 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Software composition analysis (SCA), build pipeline logs, binary integrity checks
- **Key Indicators:** Unexpected dependency changes, unsigned binaries, anomalous network calls from trusted software
- **Detection Rules:** SCA alerts on new CVEs in direct/transitive dependencies, hash mismatch on deployed binaries

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1051 Update Software | SR-3, SR-4 | Software bill of materials (SBOM) + dependency scanning in CI/CD |
| M1016 Vulnerability Scanning | RA-5 | Continuous SCA with blocking on critical CVEs |
| M1045 Code Signing | SI-7, CM-14 | Enforce signed artifacts, verify checksums before deployment |

---

## T1133 — External Remote Services

| Attribute | Details |
|:---|:---|
| Tactic | Initial Access / Persistence |
| Prevalence | 🟠 High |
| NIST SP 800-53 | AC-17, SC-7, CM-7, IA-2 |
| ISO 27001 | A.6.7 (Remote Work), A.8.20 (Network Security) |
| CIS Controls v8 | CIS 4.5, 12.3 |
| SOC 2 TSC | CC6.6 |

### Detection Guidance
- **Data Sources:** VPN/remote access logs, firewall logs, authentication events
- **Key Indicators:** VPN logins from new countries, legacy protocol use (Telnet, FTP), access outside business hours

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1042 Disable or Remove Feature or Program | CM-7 | Disable legacy remote access protocols (Telnet, RDP unless required) |
| M1032 Multi-factor Authentication | IA-2, AC-17 | MFA required on all VPN and remote desktop |
| M1030 Network Segmentation | SC-7 | Zero trust architecture for remote access |

---

## Coverage Summary — TA0001 Initial Access

| Control Domain | Coverage | Notes |
|:---|:---:|:---|
| NIST SP 800-53 | ●●●●○ | SI-8, AT-2, RA-5, AC-2, SC-7 provide strong coverage; supply chain controls (SR-*) are underused |
| ISO 27001:2022 | ●●●○○ | A.8.23 (web filtering) and A.6.3 (awareness) are high-level; lacks technical specificity |
| CIS Controls v8 | ●●●●○ | CIS 5, 7, 9, 14 directly address IG phishing, vuln management, and access control |
| SOC 2 TSC | ●●○○○ | CC6.1 and CC6.6 provide some coverage but TSC lacks preventive technical controls |
