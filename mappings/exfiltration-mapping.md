# TA0010 — Exfiltration: ATT&CK to GRC Control Mapping

**Tactic Description:** Techniques adversaries may use to steal data from a network. Once they have collected data, adversaries often package it to avoid detection while removing it through controlled channels.

---

## T1041 — Exfiltration Over C2 Channel

| Attribute | Details |
|:---|:---|
| Tactic | Exfiltration |
| Prevalence | 🟠 High |
| NIST SP 800-53 | SC-7, SC-44, DM (Data Management policies), SI-4 |
| ISO 27001 | A.5.14 (Information Transfer), A.8.20 (Network Security) |
| CIS Controls v8 | CIS 12.6, 13.9 |
| SOC 2 TSC | CC6.7, CC7.2 |

### Detection Guidance
- **Data Sources:** NDR/NTA tools, proxy logs, firewall egress logs, DNS logs, DLP platform
- **Key Indicators:** Large outbound transfers to unusual IPs/domains, C2 beaconing over HTTP/HTTPS at regular intervals, DNS queries with high entropy subdomains
- **Detection Rules:** Alert on single connection with >50MB upload, beaconing detection (fixed-interval outbound connections), JA3/JA3S TLS fingerprint matching known C2 frameworks

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1037 Filter Network Traffic | SC-7 | Strict egress filtering — whitelist-only outbound web traffic via proxy |
| M1057 Data Loss Prevention | SC-7, SC-44 | DLP with content inspection on egress traffic and email |
| M1031 Network Intrusion Prevention | SI-4 | NDR/IDPS with C2 signature detection and behavioral analytics |
| M1021 Restrict Web-Based Content | SC-7 | Block access to newly-registered domains, anonymous hosting services |

---

## T1048 — Exfiltration Over Alternative Protocol

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1048.001 Exfil Over Symmetric Encrypted Non-C2 | SC-7, SC-44, SI-4 | A.5.14, A.8.20 | CIS 12.6, 13 | CC6.7 | 🟡 Medium |
| T1048.002 Exfil Over Asymmetric Encrypted Non-C2 | SC-7, SC-44 | A.5.14, A.8.20 | CIS 12.6, 13 | CC6.7 | 🟡 Medium |
| T1048.003 Exfil Over Unencrypted Non-C2 Protocol | SC-7, SI-4, SC-44 | A.5.14, A.8.20 | CIS 12.6, 13 | CC6.7 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Firewall logs (FTP, TFTP, ICMP anomalies), DNS tunnel detection, protocol analysis in NDR
- **Key Indicators:** ICMP packets with unusually large payloads, DNS TXT queries with base64 content, unusual FTP/SFTP traffic from workstations

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1037 Filter Network Traffic | SC-7 | Block non-standard outbound protocols (FTP, ICMP tunneling) at perimeter |
| M1031 Network Intrusion Prevention | SI-4 | Protocol anomaly detection in NDR for DNS tunneling, ICMP exfil |
| M1030 Network Segmentation | SC-7 | Restrict outbound connectivity from servers to proxy only |

---

## T1567 — Exfiltration Over Web Service

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1567.001 Exfil to Code Repository | SC-7, SC-44, AC-22 | A.5.14, A.8.20, A.5.10 | CIS 3.14, 12.6 | CC6.7 | 🟡 Medium |
| T1567.002 Exfil to Cloud Storage | SC-7, SC-44, AC-22 | A.5.14, A.8.20 | CIS 3.14, 12.6 | CC6.7 | 🟠 High |
| T1567.003 Exfil to Text Storage Sites | SC-7, SC-44 | A.5.14 | CIS 9.3, 12.6 | CC6.7 | 🟡 Medium |
| T1567.004 Exfil to Generative AI | SC-7, SC-44 | A.5.14, A.5.10 | CIS 3.14, 12.6 | CC6.7 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** CASB, proxy logs, web filtering, DLP, cloud access logs
- **Key Indicators:** Large uploads to personal cloud storage (Dropbox, Google Drive), code pushes to GitHub containing corporate data patterns, bulk paste to Pastebin
- **Detection Rules:** CASB alert on bulk upload to unapproved cloud storage, DLP pattern matching on uploads to GenAI services

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1021 Restrict Web-Based Content | SC-7 | CASB to block uploads to unauthorized cloud storage; corporate-only approved apps list |
| M1057 Data Loss Prevention | SC-44 | DLP with content inspection detecting corporate data patterns in uploads |
| M1017 User Training | AT-2 | Data handling training: prohibit uploading corporate data to personal accounts or AI tools |

---

## T1020 — Automated Exfiltration

| Attribute | Details |
|:---|:---|
| Tactic | Exfiltration |
| Prevalence | 🟡 Medium |
| NIST SP 800-53 | SC-7, SI-4, SC-44 |
| ISO 27001 | A.5.14, A.8.20 |
| CIS Controls v8 | CIS 13, 12.6 |
| SOC 2 TSC | CC6.7 |

### Detection Guidance
- **Data Sources:** DLP, network flow analysis (volume anomalies), EDR process monitoring
- **Key Indicators:** Automated archiving + compression activity followed by large outbound transfer, script-based staging in temp directories

---

## T1030 — Data Transfer Size Limits

| Attribute | Details |
|:---|:---|
| Tactic | Exfiltration |
| Prevalence | 🔵 Low |
| NIST SP 800-53 | SC-7, SI-4 |
| ISO 27001 | A.5.14 |
| CIS Controls v8 | CIS 12.6, 13 |
| SOC 2 TSC | CC6.7 |

### Detection Guidance
- **Data Sources:** Network flow monitoring for slow-and-low exfil, DLP session tracking
- **Key Indicators:** Consistent small transfers (just under DLP thresholds) to same destination over time

---

## T1022 — Data Encrypted Before Exfil

| Attribute | Details |
|:---|:---|
| Tactic | Exfiltration |
| Prevalence | 🟡 Medium |
| NIST SP 800-53 | SC-7, SI-3, SI-4 |
| ISO 27001 | A.5.14, A.8.22 |
| CIS Controls v8 | CIS 13 |
| SOC 2 TSC | CC6.7 |

### Detection Guidance
- **Data Sources:** DLP with protocol decryption, EDR file system encryption events, network content inspection
- **Key Indicators:** `.zip`, `.7z`, `.rar` files created before outbound transfer, encrypted archives sent to external destinations

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1057 Data Loss Prevention | SC-44 | DLP that inspects file type, not just extension — detect encrypted archives |
| M1032 Multi-factor Authentication | IA-2 | MFA prevents threat actor from using stolen creds for direct access exfil |
| M1031 Network Intrusion Prevention | SI-4 | TLS inspection at perimeter for encrypted C2 channel exfil detection |

---

## Coverage Summary — TA0010 Exfiltration

| Control Domain | Coverage | Notes |
|:---|:---:|:---|
| NIST SP 800-53 | ●●●○○ | SC-7 (boundary protection) strong; no dedicated DLP controls beyond SC-44 |
| ISO 27001:2022 | ●●●○○ | A.5.14 (information transfer) addresses the policy layer; lacks technical DLP specifics |
| CIS Controls v8 | ●●●●○ | CIS 13 (data protection), 12.6 (network traffic monitoring) provide good coverage |
| SOC 2 TSC | ●●●○○ | CC6.7 (transmit data protection) partially addresses; needs supplemental DLP controls |
