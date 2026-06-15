# Ransomware Kill-Chain → Complete GRC Control Mapping

**Purpose:** End-to-end mapping of ransomware attack stages to GRC controls that break each stage. Use for ransomware risk assessments, tabletop exercise preparation, and building a ransomware-specific control framework.

---

## Overview

Ransomware attacks follow a consistent kill chain. Modern ransomware-as-a-service (RaaS) operations typically span **days to weeks** from initial access to encryption. This gives defenders multiple opportunities to disrupt the chain — but only if the right controls are in place and operational.

This document maps every major ransomware kill-chain stage to:
- MITRE ATT&CK techniques used
- GRC controls that prevent or detect at each stage
- Control gaps that create exposure

---

## Stage 1: Initial Access

### ATT&CK Techniques
- **T1566.001** — Spearphishing Attachment (most common ransomware entry)
- **T1190** — Exploit Public-Facing Application (2nd most common)
- **T1078** — Valid Accounts (purchased credentials from IABs)
- **T1133** — External Remote Services (exposed RDP, VPN)

### GRC Controls That Break This Stage

| Control | Framework | Implementation | Effectiveness |
|:---|:---|:---|:---:|
| Email filtering + sandbox | SI-8 / A.8.23 / CIS 9.4 | Email gateway with attachment detonation | ●●●●○ |
| Security awareness training | AT-2 / A.6.3 / CIS 14.2 | Phishing simulation + quarterly training | ●●●○○ |
| MFA on all remote access | IA-2 / A.8.5 / CIS 6.3-6.4 | FIDO2/TOTP on VPN, RDP Gateway, OWA | ●●●●● |
| Vulnerability management | RA-5 / A.8.8 / CIS 7 | 30-day critical patch SLA | ●●●●○ |
| External attack surface reduction | CM-7 / A.8.20 / CIS 4.5 | Close exposed RDP; block legacy auth | ●●●●○ |

**Stage 1 Key Insight:** MFA is the single most effective control at this stage. >80% of ransomware attacks using stolen credentials are stopped by phishing-resistant MFA.

---

## Stage 2: Execution

### ATT&CK Techniques
- **T1059.001** — PowerShell (payload delivery and execution)
- **T1059.003** — Windows Command Shell
- **T1204.001** — User Execution: Malicious Link
- **T1204.002** — User Execution: Malicious File (macro execution)

### GRC Controls That Break This Stage

| Control | Framework | Implementation | Effectiveness |
|:---|:---|:---|:---:|
| Script execution restriction | CM-7 / A.8.19 / CIS 2.7 | PowerShell Constrained Language Mode | ●●●●○ |
| Application allowlisting | CM-7 / A.8.19 / CIS 2.7 | WDAC or AppLocker | ●●●●● |
| Macro execution blocking | CM-7 / A.8.19 / CIS 9.6 | Disable macros from internet-sourced docs | ●●●●○ |
| Anti-malware with AMSI | SI-3 / A.8.7 / CIS 10.1 | AMSI-enabled EDR | ●●●●○ |
| Script block logging | AU-12 / A.8.15 / CIS 8.5 | Enable Event ID 4104 logging | ●●●○○ |

---

## Stage 3: Persistence Establishment

### ATT&CK Techniques
- **T1053.005** — Scheduled Task
- **T1547.001** — Registry Run Keys
- **T1543.003** — Windows Services
- **T1098** — Account Manipulation (backdoor accounts)

### GRC Controls That Break This Stage

| Control | Framework | Implementation | Effectiveness |
|:---|:---|:---|:---:|
| Endpoint configuration hardening | CM-7 / A.8.19 / CIS 4.1 | CIS benchmark implementation | ●●●○○ |
| Privileged access restriction | AC-6 / A.8.2 / CIS 5.4 | Least privilege — users can't create services/tasks | ●●●●○ |
| Registry protection | CM-7 / A.8.19 / CIS 4.1 | Lock autorun registry keys | ●●●○○ |
| Account change monitoring | AU-12 / A.8.15 / CIS 8.2 | Alert on account creation/modification | ●●●○○ |
| EDR behavioral detection | SI-3 / A.8.7 / CIS 10.7 | Behavioral rules for persistence patterns | ●●●●○ |

---

## Stage 4: Privilege Escalation

### ATT&CK Techniques
- **T1055** — Process Injection
- **T1068** — Exploitation for Privilege Escalation
- **T1003.001** — LSASS Memory (credential dumping for escalation)
- **T1134** — Access Token Manipulation

### GRC Controls That Break This Stage

| Control | Framework | Implementation | Effectiveness |
|:---|:---|:---|:---:|
| Credential Guard | SC-28 / A.5.17 / CIS 5.4 | Enable Windows Credential Guard | ●●●●● |
| LSASS Protected Process Light | SI-3 / A.8.7 / CIS 13.2 | `RunAsPPL = 1` registry config | ●●●●○ |
| Least privilege enforcement | AC-6 / A.8.2 / CIS 5.4 | Remove SeDebugPrivilege from standard admin | ●●●●○ |
| Patch management SLA | SI-2 / A.8.8 / CIS 7.4 | Critical privilege escalation CVEs < 30 days | ●●●●○ |
| EDR memory protection | SI-3 / A.8.7 / CIS 10.7 | Behavioral process injection detection | ●●●●○ |

**Stage 4 Key Insight:** Credential Guard + LSASS PPL together block Mimikatz-style attacks even from admin context. These two technical controls eliminate the most common ransomware escalation path.

---

## Stage 5: Internal Reconnaissance

### ATT&CK Techniques
- **T1018** — Remote System Discovery
- **T1046** — Network Service Discovery
- **T1087** — Account Discovery
- **T1482** — Domain Trust Discovery

### GRC Controls That Break This Stage

| Control | Framework | Implementation | Effectiveness |
|:---|:---|:---|:---:|
| Network segmentation | SC-7 / A.8.22 / CIS 12.2 | Prevent workstation-to-workstation scanning | ●●●●○ |
| Network monitoring | SI-4 / A.8.20 / CIS 13.3 | NDR alerts on port sweep activity | ●●●○○ |
| Honeypots/deception | SI-4 / A.8.16 / CIS 13.5 | Canary tokens that fire on access | ●●●○○ |
| Privileged access management | AC-6 / A.8.2 / CIS 5.4 | Limit network enumeration to PAM session | ●●○○○ |

---

## Stage 6: Lateral Movement

### ATT&CK Techniques
- **T1021.001** — Remote Desktop Protocol
- **T1550.002** — Pass the Hash
- **T1021.002** — SMB/Windows Admin Shares
- **T1563.002** — RDP Session Hijacking

### GRC Controls That Break This Stage

| Control | Framework | Implementation | Effectiveness |
|:---|:---|:---|:---:|
| Network segmentation (microseg.) | SC-7 / A.8.22 / CIS 12.2 | Firewall rules blocking workstation-to-workstation RDP/SMB | ●●●●● |
| Tiered Active Directory model | AC-3 / A.5.15 / CIS 5.4 | Admin accounts unique per tier; no cross-tier reuse | ●●●●● |
| Disable NTLM (enforce Kerberos) | IA-5 / A.5.17 / CIS 5.4 | `Network security: Restrict NTLM` GPO | ●●●●○ |
| Local admin password uniqueness | AC-6 / A.5.17 / CIS 5.4 | LAPS deployment on all endpoints | ●●●●○ |
| JIT privileged access | AC-17 / A.8.2 / CIS 5.4 | PAM solution with time-limited sessions | ●●●●○ |

**Stage 6 Key Insight:** Network segmentation + unique local admin passwords (LAPS) together are the most effective combination for containing lateral movement. Without these, a single compromised endpoint cascades to the entire domain.

---

## Stage 7: Data Staging and Exfiltration

### ATT&CK Techniques
- **T1074** — Data Staged (local or cloud staging)
- **T1041** — Exfiltration Over C2 Channel
- **T1048** — Exfiltration Over Alternative Protocol
- **T1567** — Exfiltration to Web Service

### GRC Controls That Break This Stage

| Control | Framework | Implementation | Effectiveness |
|:---|:---|:---|:---:|
| DLP (Data Loss Prevention) | SC-44 / A.5.14 / CIS 3.14 | Content inspection on egress + cloud uploads | ●●●○○ |
| Egress filtering via proxy | SC-7 / A.8.20 / CIS 12.6 | Whitelist-only outbound HTTP/HTTPS via proxy | ●●●●○ |
| CASB | SC-7, SC-44 / A.5.14 / CIS 3.14 | Block unauthorized cloud storage uploads | ●●●●○ |
| NDR/NTA | SI-4 / A.8.20 / CIS 13.3 | Detect large data staging and transfer anomalies | ●●●○○ |
| Data classification | AC-16 / A.5.12 / CIS 3.7 | Tag sensitive data to enable DLP rule targeting | ●●○○○ |

---

## Stage 8: Pre-Encryption Actions

### ATT&CK Techniques
- **T1490** — Inhibit System Recovery (VSS deletion)
- **T1222** — File and Directory Permissions Modification
- **T1562** — Impair Defenses (disable security tools, AV)

### GRC Controls That Break This Stage

| Control | Framework | Implementation | Effectiveness |
|:---|:---|:---|:---:|
| VSS deletion monitoring | CP-9 / A.8.13 / CIS 11.3 | Alert on `vssadmin delete shadows` commands | ●●●●○ |
| Security tool tamper protection | AU-9 / A.8.19 / CIS 10.6 | EDR tamper protection enabled; remote management only | ●●●●● |
| Privileged command monitoring | AU-12 / A.8.15 / CIS 8.5 | Alert on high-risk administrative commands | ●●●○○ |
| AV/EDR self-healing | SI-3 / A.8.7 / CIS 10.6 | Centralized management; auto-restart on process kill | ●●●○○ |

---

## Stage 9: Encryption (Final Stage)

### ATT&CK Techniques
- **T1486** — Data Encrypted for Impact

### GRC Controls That Break This Stage

| Control | Framework | Implementation | Effectiveness |
|:---|:---|:---|:---:|
| Behavioral ransomware detection | SI-3 / A.8.7 / CIS 10.7 | EDR canary files + mass-rename detection | ●●●●○ |
| Application allowlisting | CM-7 / A.8.19 / CIS 2.7 | Block unknown executables from running | ●●●●● |
| Immutable backups | CP-9 / A.8.13 / CIS 11.4 | Air-gapped, versioned, tested backups | ●●●●● |
| Network share access control | AC-3 / A.5.15 / CIS 3.3 | Restrict who can write to shared drives | ●●●○○ |
| Incident response plan | IR-4 / A.5.24 / CIS 17 | Tested IR playbook with ransomware scenario | ●●●○○ |

**Stage 9 Key Insight:** Immutable backups are the *only* control that completely defeats ransomware leverage. All other controls reduce likelihood; backups guarantee recoverability regardless of outcome.

---

## Ransomware Defense Maturity Model

```
MATURITY LEVEL 1 — Basic Hygiene (IG1 / SOC 2 minimum)
  ✓ MFA on remote access
  ✓ Patching < 30 days (critical)
  ✓ Tested backups (offline copy)
  ✓ Email filtering
  Risk Reduction: ~40%

MATURITY LEVEL 2 — Intermediate Defense (IG2 / NIST Moderate)
  + Level 1 controls
  ✓ EDR behavioral detection
  ✓ LAPS (unique local admin passwords)
  ✓ Network segmentation (server/workstation zones)
  ✓ Privileged Access Management
  ✓ Centralized logging + SIEM
  Risk Reduction: ~70%

MATURITY LEVEL 3 — Advanced Defense (IG3 / NIST High)
  + Level 2 controls
  ✓ Application allowlisting (WDAC)
  ✓ Credential Guard + LSASS PPL
  ✓ Tiered Active Directory model
  ✓ Microsegmentation (East-West controls)
  ✓ DLP + CASB
  ✓ Immutable, air-gapped backups (tested)
  ✓ Deception technology (canary tokens)
  Risk Reduction: ~90%
```

---

## Ransomware Tabletop Exercise Scenario → Control Validation

```
SCENARIO: "BlackCat-Style" Ransomware Attack

Day 0:  Phishing email with macro document received
         → Validate: SI-8 (email sandbox), AT-2 (user awareness)

Day 0:  User opens attachment; macro executes PowerShell beacon
         → Validate: CM-7 (macro block via GPO?), SI-3 (AMSI catch?)

Day 1:  C2 established; reconnaissance begins
         → Validate: SC-7 (egress filtering?), SI-4 (C2 detection?)

Day 2:  Credential dumping (LSASS)
         → Validate: SC-28 (Credential Guard?), SI-3 (EDR PPL alert?)

Day 3:  Lateral movement via PtH + RDP
         → Validate: AC-6 (LAPS?), SC-7 (workstation firewall rules?)

Day 5:  Data staged and exfiltrated (10GB to cloud storage)
         → Validate: SC-44 (DLP?), CASB (cloud upload alert?)

Day 7:  Shadow copy deletion; ransomware deployed
         → Validate: CP-9 (offline backups survive?), SI-3 (behavioral detection?)
         → Measure: Time to detect, time to respond, time to recover

DISCUSSION QUESTIONS:
  1. At which stage was the attack first detectable? Was it detected?
  2. Which GRC controls failed? Which prevented escalation?
  3. What is the RTO/RPO given our current backup posture?
  4. Which risk register entries need to be updated based on findings?
```
