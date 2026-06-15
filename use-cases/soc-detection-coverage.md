# SOC Detection Coverage → GRC Control Mapping

**Purpose:** Maps SOC detection capabilities (log sources, SIEM rules, alerting) to GRC controls. Helps GRC practitioners validate that compliance-required monitoring controls are operationally effective, and helps SOC teams justify detection investments in GRC terms.

---

## Detection Capability → GRC Control Cross-Reference

| SOC Capability | ATT&CK Techniques Detected | NIST Control | ISO 27001 | CIS Control | SOC 2 TSC |
|:---|:---|:---|:---|:---|:---|
| Email gateway + sandbox | T1566.001/002 | SI-8 | A.8.23 | CIS 9.4 | CC6.8 |
| EDR with behavioral rules | T1055, T1059, T1003, T1562, T1486 | SI-3 | A.8.7 | CIS 10.7 | CC6.8, CC7.2 |
| SIEM (log correlation) | T1078, T1110, T1021, T1053, T1136 | AU-6, AU-12 | A.8.15, A.8.16 | CIS 8.11 | CC7.2 |
| NDR/NTA | T1041, T1071, T1048 | SC-7, SI-4 | A.8.20 | CIS 13.3 | CC7.2 |
| Identity/UEBA | T1078, T1110.003, T1134 | IA-2, AC-2 | A.8.16 | CIS 5.4 | CC6.1 |
| Vulnerability scanner | T1190, T1068 | RA-5 | A.8.8 | CIS 7.4 | CC7.1 |
| DLP | T1041, T1048, T1567 | SC-44 | A.5.14 | CIS 3.14, 13.9 | CC6.7 |
| CASB | T1567.002/003/004 | SC-7 | A.5.14 | CIS 3.14 | CC6.7 |
| DNS filtering/RPZ | T1071.004, T1566.002 | SC-7 | A.8.20, A.8.23 | CIS 9.2 | CC6.8 |
| WAF | T1190 | SC-7, RA-5 | A.8.8, A.8.20 | CIS 7.4 | CC7.1 |
| FIM (File Integrity Mon.) | T1070, T1036, T1491 | SI-7 | A.8.15 | CIS 8.5 | CC7.2 |
| PAM/session recording | T1021, T1078.002, T1134 | AC-6, AC-17 | A.8.2, A.6.7 | CIS 5.4 | CC6.1 |
| Cloud security posture (CSPM) | T1098.003, T1078.004, T1530 | AC-2, AU-12 | A.5.15, A.5.18 | CIS 5.5 | CC6.1 |
| Backup monitoring | T1486, T1490 | CP-9 | A.8.13 | CIS 11.5 | A1.2 |

---

## SOC Tier Mapping: Detection Depth by Control Framework

### Tier 1 SOC: Alert Triage (Basic Detection)

Minimum viable detection tooling and GRC controls satisfied:

```
CAPABILITY          GRC CONTROLS VALIDATED           ATT&CK COVERAGE
────────────────────────────────────────────────────────────────────
Email security      SI-8, AT-2 | A.8.23 | CIS 9      T1566 family
AV/EPP              SI-3 | A.8.7 | CIS 10.1           T1027, T1059 (partial)
Firewall logging    SC-7 | A.8.20 | CIS 4.5           T1021, T1133 (partial)
Auth log collection AU-12 | A.8.15 | CIS 8.2          T1078, T1110
Vulnerability scan  RA-5 | A.8.8 | CIS 7.1            T1190
────────────────────────────────────────────────────────────────────
Coverage of top 25 ATT&CK techniques: ~35%
```

### Tier 2 SOC: Threat Detection (Intermediate)

```
CAPABILITY          GRC CONTROLS VALIDATED                   ATT&CK COVERAGE
────────────────────────────────────────────────────────────────────────────
EDR behavioral      SI-3, SC-39 | A.8.7 | CIS 10.7          T1055, T1003, T1059
SIEM correlation    AU-6, AU-12 | A.8.15, A.8.16 | CIS 8.11  T1053, T1136, T1078
NDR/NTA             SC-7, SI-4 | A.8.20 | CIS 13.3           T1041, T1071, T1021
UEBA                IA-2, AC-2 | A.8.16 | CIS 5.4            T1078, T1110.003
DNS filtering       SC-7 | A.8.23 | CIS 9.2                  T1071.004
DLP                 SC-44 | A.5.14 | CIS 3.14                T1041, T1567
────────────────────────────────────────────────────────────────────────────
Coverage of top 25 ATT&CK techniques: ~65%
```

### Tier 3 SOC: Advanced Threat Hunting (Full Capability)

```
CAPABILITY          GRC CONTROLS VALIDATED               ATT&CK COVERAGE
────────────────────────────────────────────────────────────────────────
Threat intel feed   RA-3 | A.5.7 | CIS 17.9             All tactics (IOC)
PAM/session rec.    AC-6, AC-17 | A.8.2 | CIS 5.4        T1078, T1021, T1134
CASB                SC-7, SC-44 | A.5.14 | CIS 3.14      T1567 family
CSPM                AC-2, AU-12 | A.5.18 | CIS 5.5       T1098, T1530
Deception/honeypots SI-4 | A.8.16 | CIS 13.5 (IG3)       T1046, T1018 (discovery)
Sandbox (inline)    SC-44, SI-3 | A.8.7 | CIS 9.4        T1566, T1027, T1059
────────────────────────────────────────────────────────────────────────
Coverage of top 25 ATT&CK techniques: ~90%
```

---

## Detection Use Cases → Control Validation Evidence

### Use Case 1: Credential Dumping Detection (T1003.001)

**What SOC Detects:**
- Sysmon Event 10: Process access to `lsass.exe` from non-Windows process
- EDR alert: Memory read on LSASS process space
- Windows Event 4656/4663: Handle request to LSASS object

**GRC Controls Validated:**
| Control | How Detection Provides Evidence |
|:---|:---|
| NIST SI-3 (Malware Protection) | EDR behavioral rule firing demonstrates SI-3 effectiveness |
| NIST AU-12 (Audit Record Gen.) | Sysmon Event 10 proves audit record generation for credential access |
| CIS 13.2 (Host-Based IDS) | EDR alert validates CIS 13.2 implementation |
| SOC 2 CC7.2 (Anomaly Detection) | UEBA/EDR alert demonstrates CC7.2 monitoring implementation |

**Audit Evidence:** EDR alert screenshot + SIEM search showing event timeline

---

### Use Case 2: Lateral Movement Detection (T1021.001 RDP)

**What SOC Detects:**
- Network flow: RDP (3389) from workstation-to-workstation
- Windows Event 4624 (LogonType 10) from unusual source
- UEBA: RDP from new source IP for given user

**GRC Controls Validated:**
| Control | How Detection Provides Evidence |
|:---|:---|
| NIST AC-17 (Remote Access) | Network monitoring confirms remote access controls enforced |
| NIST SC-7 (Boundary Protection) | Firewall logs showing rule enforcement on RDP |
| CIS 4.5 (Firewall on Servers) | Rule preventing workstation-to-workstation RDP validated by block log |
| SOC 2 CC6.6 (Remote Access) | Authentication logs with anomaly alert validate CC6.6 |

---

### Use Case 3: Ransomware Behavior Detection (T1486)

**What SOC Detects:**
- EDR behavioral: >100 file renames/min from single process
- Windows Event: `vssadmin delete shadows` execution
- Backup system: Shadow copy deletion alert
- File system: Encrypted file extension spread detected

**GRC Controls Validated:**
| Control | How Detection Provides Evidence |
|:---|:---|
| NIST SI-3 (Malware Protection) | EDR behavioral detection firing demonstrates protection capability |
| NIST CP-9 (System Backup) | Backup integrity alert shows backup monitoring in place |
| NIST IR-4 (Incident Handling) | SOC response to alert validates incident handling procedures |
| CIS 10.7 (Behavioral Anti-Malware) | Behavioral EDR rule validates CIS 10.7 implementation |
| SOC 2 CC7.5 (Breach Identification) | Alert chain demonstrates incident detection and response workflow |

---

## SIEM Detection Rules → Control Mapping

### High-Value SIEM Rules by GRC Priority

| SIEM Rule | ATT&CK Technique | GRC Control | Alert Priority |
|:---|:---|:---|:---:|
| Event 1102: Security log cleared | T1070.001 | AU-9, CIS 8.9 | P1 — immediate |
| lsass.exe memory read (non-system) | T1003.001 | SI-3, CIS 13.2 | P1 — immediate |
| `vssadmin delete shadows` execution | T1490 | CP-9, CIS 11.3 | P1 — immediate |
| Scheduled task creation (non-admin) | T1053.005 | CM-7, CIS 4.1 | P2 — 15 min |
| Workstation-to-workstation RDP | T1021.001 | AC-17, CIS 4.5 | P2 — 15 min |
| Multiple failed logins → success | T1110 | AC-7, CIS 6.3 | P2 — 15 min |
| New user account creation | T1136 | AC-2, CIS 5.1 | P2 — 30 min |
| Admin account outside business hours | T1078.002 | AC-2, CIS 5.3 | P2 — 30 min |
| Security tool service stopped | T1562.001 | AU-9, CIS 10.6 | P1 — immediate |
| Large outbound transfer (>500MB) | T1041 | SC-44, CIS 13.9 | P2 — 15 min |
| PowerShell Event 4104 (encoded cmd) | T1059.001 | CM-7, CIS 2.7 | P2 — 15 min |
| DCSync replication from non-DC | T1003.006 | IA-5, CIS 5.4 | P1 — immediate |

---

## SOC Metrics → GRC Reporting

Map SOC operational metrics to GRC framework requirements:

| SOC Metric | Target | GRC Requirement Satisfied |
|:---|:---:|:---|
| Mean Time to Detect (MTTD) for P1 alerts | <15 min | NIST IR-4, ISO A.5.24, CIS 17.4 |
| Mean Time to Respond (MTTR) | <4 hours (P1) | NIST IR-4, ISO A.5.24 |
| Alert coverage of P1 ATT&CK techniques | 100% | NIST SI-4, AU-12, SOC 2 CC7.2 |
| False positive rate | <5% | NIST AU-6, SI-4 (quality of alerts) |
| Log source availability | >99.5% | NIST AU-12, AU-9, CIS 8.3 |
| Vulnerability scan coverage | 100% of internet-facing assets | NIST RA-5, CIS 7.6 |
| Patch SLA adherence (critical CVEs) | >95% within 30 days | NIST SI-2, CIS 7.7 |
