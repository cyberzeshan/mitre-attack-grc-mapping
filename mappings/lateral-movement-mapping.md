# TA0008 — Lateral Movement: ATT&CK to GRC Control Mapping

**Tactic Description:** Techniques that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target and subsequently gaining access to it.

---

## T1021 — Remote Services

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1021.001 Remote Desktop Protocol (RDP) | AC-17, SC-7, CM-7, AU-12 | A.6.7, A.8.20 | CIS 4.5, 12.3 | CC6.6 | 🟠 High |
| T1021.002 SMB/Windows Admin Shares | AC-17, SC-7, CM-7 | A.8.20, A.6.7 | CIS 4.5, 12 | CC6.6 | 🟠 High |
| T1021.003 Distributed Component Object Model | CM-7, SC-7 | A.8.19, A.8.20 | CIS 4.1, 12 | CC6.6 | 🟡 Medium |
| T1021.004 SSH | AC-17, SC-7, IA-5 | A.6.7, A.8.20 | CIS 4.5, 12 | CC6.6 | 🟡 Medium |
| T1021.006 Windows Remote Management (WinRM) | AC-17, CM-7, SC-7 | A.6.7, A.8.20 | CIS 4.5, 12 | CC6.6 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Windows Event Log 4624 (LogonType 10 = RDP, 3 = Network), network flows, firewall logs, authentication events
- **Key Indicators:** RDP connections originating from servers (East-West traffic), admin shares accessed outside change windows, RDP from workstation to workstation
- **Detection Rules:** Alert on workstation-to-workstation RDP, `net use \\` commands from non-admin context, SMB connections following credential access events

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1035 Limit Access to Resource Over Network | SC-7, AC-17 | Restrict RDP to jump servers only; block workstation-to-workstation via firewall (CIS 12.3) |
| M1032 Multi-factor Authentication | IA-2 | MFA on all RDP/Remote Desktop Gateway connections |
| M1026 Privileged Account Management | AC-6 | Just-in-time (JIT) privileged access; dedicated PAW for admin RDP |
| M1030 Network Segmentation | SC-7 | Microsegmentation preventing lateral East-West movement |
| M1042 Disable or Remove Feature | CM-7 | Disable SMB v1; disable admin shares on workstations |

---

## T1550 — Use Alternate Authentication Material

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1550.001 Application Access Token | IA-5, AC-3, AU-12 | A.5.17, A.8.5 | CIS 5.5 | CC6.1 | 🟡 Medium |
| T1550.002 Pass the Hash (PtH) | IA-5, AC-6, SC-28 | A.5.17, A.8.5 | CIS 5.4, 13 | CC6.1 | 🟠 High |
| T1550.003 Pass the Ticket | IA-5, AC-6, SC-28 | A.5.17, A.8.5 | CIS 5.4 | CC6.1 | 🟠 High |
| T1550.004 Web Session Cookie | IA-5, SC-8, SC-28 | A.5.17, A.8.20 | CIS 5.5, 12 | CC6.1 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Windows Event Log 4624 (LogonType 9 = NewCredentials), 4648, network authentication logs, UEBA
- **Key Indicators:** NTLM authentication from unusual source hosts, Kerberos tickets used from different IP than obtained, access token anomalies in cloud platforms
- **Detection Rules:** Alert on NTLM auth bypassing standard authentication flows, anomalous TGT usage patterns (different source IP)

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1051 Update Software | SI-2 | Patch systems to remove NTLM vulnerabilities; upgrade to Kerberos where possible |
| M1052 User Account Control | CM-6 | Enable Local Account Token Filter Policy to prevent PtH for remote admin |
| M1026 Privileged Account Management | AC-6 | Tiered Active Directory model: Admin accounts unique per tier, no cross-tier reuse |
| M1043 Credential Access Protection | SC-28 | Enable Credential Guard to protect NTLM hashes and Kerberos tickets |
| M1032 Multi-factor Authentication | IA-2 | MFA prevents PtH from being sufficient for modern cloud/SaaS services |

---

## T1534 — Internal Spearphishing

| Attribute | Details |
|:---|:---|
| Tactic | Lateral Movement |
| Prevalence | 🟡 Medium |
| NIST SP 800-53 | AT-2, SC-7, SI-3, SI-8 |
| ISO 27001 | A.6.3, A.8.23 |
| CIS Controls v8 | CIS 9, 14.2 |
| SOC 2 TSC | CC2.2, CC6.1 |

### Detection Guidance
- **Data Sources:** Email gateway logs (internal mail), collaboration platform logs (Teams/Slack), URL filtering
- **Key Indicators:** Internal emails with atypical attachments or links, emails sent from compromised accounts to executives

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1049 Antivirus/Antimalware | SI-3, SI-8 | Apply email filtering rules also to internal mail paths |
| M1017 User Training | AT-2 | Training to question internal emails requesting credential entry |

---

## T1563 — Remote Service Session Hijacking

| Sub-Technique | NIST SP 800-53 Rev 5 | ISO 27001:2022 Annex A | CIS Controls v8 | SOC 2 TSC | Prevalence |
|:---|:---|:---|:---|:---|:---:|
| T1563.001 SSH Hijacking | AC-17, IA-5, AU-12 | A.6.7, A.8.20 | CIS 4.5, 12 | CC6.6 | 🔵 Low |
| T1563.002 RDP Hijacking | AC-17, CM-7, AU-12 | A.6.7, A.8.20 | CIS 4.5, 12 | CC6.6 | 🟡 Medium |

### Detection Guidance
- **Data Sources:** Windows Event Log 4778/4779 (session reconnect/disconnect), network session monitoring
- **Key Indicators:** RDP session hijacking via `tscon.exe` with SYSTEM privileges, session theft from disconnected sessions

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1026 Privileged Account Management | AC-6 | JIT access prevents long-lived disconnected sessions |
| M1030 Network Segmentation | SC-7 | Isolate admin hosts; privileged access workstations (PAWs) |
| M1047 Audit | AU-12 | Alert on `tscon.exe` execution; monitor session lifecycle events |

---

## T1570 — Lateral Tool Transfer

| Attribute | Details |
|:---|:---|
| Tactic | Lateral Movement |
| Prevalence | 🟡 Medium |
| NIST SP 800-53 | CM-7, SC-7, SI-3, AU-12 |
| ISO 27001 | A.8.19, A.8.20 |
| CIS Controls v8 | CIS 4.1, 12.2 |
| SOC 2 TSC | CC7.2 |

### Detection Guidance
- **Data Sources:** Network flows (SMB/HTTP traffic between endpoints), EDR file creation events, DLP
- **Key Indicators:** Tools like `psexec.exe`, `cobalt strike`, `metasploit` payloads transferred between hosts, unusual file drops in `C:\Windows\Temp`

### Mitigations → Control Implementations
| ATT&CK Mitigation | GRC Control | Implementation |
|:---|:---|:---|
| M1037 Filter Network Traffic | SC-7 | Restrict inbound SMB/RPC between workstations at firewall level |
| M1038 Execution Prevention | CM-7 | Application allowlisting prevents execution of transferred tools |
| M1049 Antivirus/Antimalware | SI-3 | Real-time AV scanning with hash-based and behavioral detection |

---

## Coverage Summary — TA0008 Lateral Movement

| Control Domain | Coverage | Notes |
|:---|:---:|:---|
| NIST SP 800-53 | ●●●●○ | AC-17, SC-7, IA-5 provide strong coverage; network segmentation (SC-7) is the key control |
| ISO 27001:2022 | ●●●○○ | A.8.20 (network security) and A.6.7 (remote work) partially address; needs technical specifics |
| CIS Controls v8 | ●●●●○ | CIS 4.5, 12.3 directly restrict RDP/remote services; microsegmentation recommended |
| SOC 2 TSC | ●●●○○ | CC6.6 (remote access controls) covers external; internal lateral movement less prescriptive |
