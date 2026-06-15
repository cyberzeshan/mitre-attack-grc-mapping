# ATT&CK Technique Risk Ratings

**Purpose:** Provides a structured risk rating for the top ATT&CK Enterprise techniques based on prevalence (frequency of use in real-world incidents) and impact (potential damage). Use this to prioritize detection and control investments.

---

## Risk Scoring Methodology

```
RISK SCORE = (Prevalence Score × 0.4) + (Impact Score × 0.4) + (Detection Difficulty × 0.2)

PREVALENCE (1–5):
  5 = Seen in >50% of incident investigations (Critical)
  4 = Seen in >25% of incidents (High)
  3 = Seen in >10% of incidents (Medium)
  2 = Seen in <10% of incidents (Low)
  1 = Rare/theoretical (Very Low)

IMPACT (1–5):
  5 = Full compromise, data destruction, ransomware, major operational disruption
  4 = Significant lateral movement, credential compromise, substantial data exposure
  3 = Moderate persistence or privilege escalation
  2 = Limited scope or recoverable
  1 = Minimal real-world impact

DETECTION DIFFICULTY (1–5):
  5 = Very hard to detect (living-off-the-land, legitimate tool abuse)
  4 = Hard (requires behavioral analytics or specialized tooling)
  3 = Moderate (detectable with proper logging and SIEM rules)
  2 = Moderate-Easy (signature detection available)
  1 = Easy (noisy, well-detected by basic AV/IDS)
```

---

## Master Risk Rating Table

| ATT&CK ID | Technique | Tactic | Prevalence | Impact | Detection Difficulty | **Risk Score** | Priority |
|:---|:---|:---|:---:|:---:|:---:|:---:|:---:|
| T1566.001 | Spearphishing Attachment | Initial Access | 5 | 4 | 3 | **4.2** | 🔴 P1 |
| T1078 | Valid Accounts | Init Access/Persistence | 5 | 5 | 4 | **4.8** | 🔴 P1 |
| T1059.001 | PowerShell | Execution | 5 | 4 | 4 | **4.4** | 🔴 P1 |
| T1486 | Data Encrypted for Impact | Impact | 4 | 5 | 3 | **4.2** | 🔴 P1 |
| T1003.001 | LSASS Memory | Credential Access | 5 | 5 | 3 | **4.6** | 🔴 P1 |
| T1190 | Exploit Public-Facing App | Initial Access | 4 | 5 | 3 | **4.2** | 🔴 P1 |
| T1071.001 | Web Protocols (C2) | Command & Control | 4 | 4 | 5 | **4.2** | 🔴 P1 |
| T1055 | Process Injection | Defense Evasion/PrivEsc | 4 | 4 | 5 | **4.2** | 🔴 P1 |
| T1021.001 | Remote Desktop Protocol | Lateral Movement | 4 | 4 | 3 | **3.8** | 🟠 P2 |
| T1562.001 | Disable Security Tools | Defense Evasion | 4 | 4 | 3 | **3.8** | 🟠 P2 |
| T1041 | Exfiltration Over C2 | Exfiltration | 4 | 4 | 4 | **4.0** | 🟠 P2 |
| T1110 | Brute Force | Credential Access | 3 | 3 | 2 | **2.8** | 🟡 P3 |
| T1027 | Obfuscated Files | Defense Evasion | 3 | 3 | 5 | **3.4** | 🟡 P3 |
| T1053.005 | Scheduled Task | Persistence | 3 | 3 | 3 | **3.0** | 🟡 P3 |
| T1136 | Create Account | Persistence | 3 | 3 | 2 | **2.8** | 🟡 P3 |
| T1550.002 | Pass the Hash | Lateral Movement | 4 | 4 | 4 | **4.0** | 🟠 P2 |
| T1558.003 | Kerberoasting | Credential Access | 4 | 4 | 4 | **4.0** | 🟠 P2 |
| T1070.001 | Clear Windows Event Logs | Defense Evasion | 4 | 3 | 2 | **3.2** | 🟡 P3 |
| T1490 | Inhibit System Recovery | Impact | 4 | 5 | 2 | **4.0** | 🟠 P2 |
| T1567.002 | Exfil to Cloud Storage | Exfiltration | 3 | 4 | 4 | **3.6** | 🟠 P2 |
| T1195.001 | Software Dependencies | Initial Access | 3 | 5 | 5 | **4.0** | 🟠 P2 |
| T1548.002 | Bypass UAC | Privilege Escalation | 3 | 3 | 3 | **3.0** | 🟡 P3 |
| T1134.001 | Token Impersonation | Privilege Escalation | 3 | 4 | 4 | **3.6** | 🟠 P2 |
| T1036.005 | Masquerade by Name | Defense Evasion | 3 | 3 | 4 | **3.2** | 🟡 P3 |
| T1218.011 | Rundll32 (LOLBin) | Defense Evasion | 3 | 3 | 4 | **3.2** | 🟡 P3 |

---

## P1 Techniques — Immediate Action Required

### T1078 — Valid Accounts (Risk Score: 4.8 — Highest)

```
Why it tops the list:
  - Used in >80% of ransomware incidents (entry + lateral movement)
  - Often invisible in logs (legitimate creds = no malware signature)
  - Enables persistence, lateral movement, and exfiltration simultaneously

Key Controls:
  NIST:  IA-2 (MFA), AC-2 (account lifecycle), AC-6 (least privilege)
  CIS:   5.3 (disable dormant), 5.4 (restrict admin), 6.3 (MFA)
  ISO:   A.5.17, A.8.5
  SOC2:  CC6.1
```

### T1003.001 — LSASS Memory Dump (Risk Score: 4.6)

```
Why it's critical:
  - Enables all subsequent credential-based attacks (PtH, PtT, DCSync)
  - Mimikatz variants still bypass many AV solutions
  - Single successful dump → full domain compromise path

Key Controls:
  NIST:  IA-5, SC-28, CM-6 (PPL for LSASS)
  CIS:   5.4 (restrict admin), 13.2 (EDR)
  ISO:   A.5.17, A.8.5
  SOC2:  CC6.1
```

### T1059.001 — PowerShell (Risk Score: 4.4)

```
Why it's critical:
  - Enables fileless malware, bypasses disk-based AV
  - Used in >60% of ransomware kill chains
  - Constrained Language Mode is underdeployed

Key Controls:
  NIST:  CM-7 (constrained mode), AU-12 (script block logging 4104)
  CIS:   2.7 (script allowlisting), 8.2 (logging)
  ISO:   A.8.19
  SOC2:  CC7.2
```

---

## Risk Matrix Visual

```
IMPACT →
         Low (1)    Med (3)    High (5)
         ┌──────────┬──────────┬──────────┐
High (5) │  P3      │  P2      │  P1 🔴   │  ← T1078, T1003, T1486
         │          │          │          │
Med  (3) │  P4      │  P3      │  P2 🟠   │  ← T1021, T1041, T1490
         │          │          │          │
Low  (1) │  P5      │  P4      │  P3 🟡   │
         └──────────┴──────────┴──────────┘
↑ PREVALENCE
```

---

## Risk Rating by Tactic

| ATT&CK Tactic | Max Risk Score | Avg Risk Score | Highest Risk Technique |
|:---|:---:|:---:|:---|
| Initial Access | 4.8 | 4.1 | T1078 (Valid Accounts) |
| Execution | 4.4 | 3.8 | T1059.001 (PowerShell) |
| Persistence | 3.0 | 2.9 | T1053.005 (Scheduled Task) |
| Privilege Escalation | 4.2 | 3.6 | T1055 (Process Injection) |
| Defense Evasion | 4.2 | 3.4 | T1562.001 (Disable Security Tools) |
| Credential Access | 4.6 | 3.8 | T1003.001 (LSASS Dump) |
| Lateral Movement | 4.0 | 3.7 | T1550.002 (Pass the Hash) |
| Exfiltration | 4.0 | 3.5 | T1041 (Exfil Over C2) |
| Impact | 4.2 | 4.0 | T1486 (Ransomware) |

---

## Prioritized Control Investment Guidance

Based on risk scores, invest in this order:

| Priority | Control Investment | ATT&CK Risk Reduction | Cost |
|:---:|:---|:---:|:---:|
| 1 | MFA on all accounts (IA-2) | -0.8 to T1078 | Low |
| 2 | EDR with behavioral detection | -0.6 to T1003, T1055, T1059 | Medium |
| 3 | Privileged Access Management | -0.5 to T1078, T1021, T1550 | Medium |
| 4 | Immutable backups (CP-9) | Defeats T1486 | Low-Medium |
| 5 | Network segmentation (SC-7) | -0.4 to T1021, T1041, T1071 | High |
| 6 | Vulnerability management SLA | -0.4 to T1190, T1068 | Low |
| 7 | PowerShell Constrained Mode + logging | -0.4 to T1059.001 | Low |
| 8 | Central SIEM + log protection | -0.3 to T1070, T1562 | Medium |
