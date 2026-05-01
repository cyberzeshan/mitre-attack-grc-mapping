# 🗺️ MITRE ATT&CK → GRC Control Mapping

<div align="center">

![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK_v15-FF0000?style=flat-square&logoColor=white)
![NIST 800-53](https://img.shields.io/badge/NIST_SP_800--53_Rev5-003087?style=flat-square&logoColor=white)
![ISO 27001](https://img.shields.io/badge/ISO_27001%3A2022-0066CC?style=flat-square&logoColor=white)
![CIS Controls](https://img.shields.io/badge/CIS_Controls_v8-00A86B?style=flat-square&logoColor=white)
![SOC2](https://img.shields.io/badge/SOC_2_TSC-4A154B?style=flat-square&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

**Comprehensive mapping of MITRE ATT&CK Enterprise v15 techniques to NIST SP 800-53 Rev 5, ISO 27001:2022 Annex A, CIS Controls v8, and SOC 2 TSC — with detection guidance, data sources, and GRC control recommendations.**

</div>

---

## 📖 Overview

The gap between **threat intelligence** and **governance frameworks** is where security programs fail. GRC practitioners know their controls; threat intelligence teams know the adversary. This mapping bridges both worlds.

For every major ATT&CK technique, this repository provides:
- Which **GRC controls** address it (NIST, ISO, CIS, SOC 2)
- What **data sources and detections** to implement
- What **mitigations** ATT&CK recommends (mapped to real control implementations)
- **Risk scoring guidance** for each technique based on prevalence and impact

---

## 📂 Repository Structure

```
mitre-attack-grc-mapping/
│
├── mappings/
│   ├── initial-access-mapping.md        # TA0001 — Phishing, supply chain, external services
│   ├── persistence-mapping.md           # TA0003 — Scheduled tasks, registry, boot persistence
│   ├── privilege-escalation-mapping.md  # TA0004 — Token manipulation, abuse elevation
│   ├── defense-evasion-mapping.md       # TA0005 — Log clearing, masquerading, obfuscation
│   ├── credential-access-mapping.md     # TA0006 — Credential dumping, brute force, keylogging
│   ├── lateral-movement-mapping.md      # TA0008 — Pass the hash, RDP, internal spearphishing
│   ├── exfiltration-mapping.md          # TA0010 — Exfil over C2, web service, physical medium
│   └── impact-mapping.md               # TA0040 — Ransomware, data destruction, defacement
│
├── by-framework/
│   ├── nist-800-53-to-attck.md          # NIST control → ATT&CK techniques it mitigates
│   ├── iso27001-annex-a-to-attck.md     # ISO Annex A control → ATT&CK coverage
│   ├── cis-v8-to-attck.md               # CIS Control → ATT&CK coverage gaps
│   └── soc2-tsc-to-attck.md             # SOC 2 TSC → ATT&CK technique coverage
│
├── risk-scoring/
│   ├── technique-risk-ratings.md        # Prevalence + impact scoring for top techniques
│   └── control-gap-analysis.md          # Where your controls leave ATT&CK coverage gaps
│
└── use-cases/
    ├── purple-team-grc-alignment.md     # How to use this for purple team exercises
    ├── soc-detection-coverage.md        # Mapping SOC detections to GRC controls
    └── ransomware-defense-mapping.md    # Full ransomware kill-chain → control mapping
```

---

## 🗺️ Master Mapping Table — Top ATT&CK Techniques (by Prevalence)

| ATT&CK ID | Technique | Tactic | Prevalence | NIST SP 800-53 Controls | ISO 27001 Annex A | CIS Controls v8 | SOC 2 TSC | Detection Source |
|:---|:---|:---|:---:|:---|:---|:---|:---|:---|
| T1566.001 | Phishing: Spearphishing Attachment | Initial Access | 🔴 Critical | SI-8, AT-2, SC-7 | A.6.3, A.8.23 | CIS 9, 14 | CC6.1, CC2.2 | Email gateway logs, sandbox detonation |
| T1078 | Valid Accounts | Initial Access / Persistence | 🔴 Critical | AC-2, AC-3, IA-5 | A.5.15–5.18 | CIS 5, 6 | CC6.1, CC6.2 | Authentication logs, UEBA |
| T1059.001 | Command & Scripting: PowerShell | Execution | 🔴 Critical | CM-7, SI-3, AU-12 | A.8.19, A.8.15 | CIS 4, 8 | CC7.2 | PowerShell logging (4103/4104), EDR |
| T1055 | Process Injection | Defense Evasion / Privilege Escalation | 🟠 High | SI-3, CM-7, SC-39 | A.8.8, A.8.19 | CIS 10, 13 | CC7.2 | EDR process telemetry, memory analysis |
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access | 🔴 Critical | IA-5, SC-28, AC-6 | A.5.17, A.8.5 | CIS 5.4, 13 | CC6.1 | EDR, Windows Event 4656/4663 |
| T1021.001 | Remote Desktop Protocol | Lateral Movement | 🟠 High | AC-17, SC-7, CM-7 | A.6.7, A.8.20 | CIS 4.5, 12 | CC6.6 | Network flows, RDP authentication logs |
| T1486 | Data Encrypted for Impact (Ransomware) | Impact | 🔴 Critical | CP-9, SC-28, IR-4 | A.5.29, A.8.13 | CIS 11, 17 | CC7.5, A1.2 | File system monitoring, EDR, backup integrity |
| T1190 | Exploit Public-Facing Application | Initial Access | 🟠 High | RA-5, SI-2, CM-7 | A.8.8, A.8.25 | CIS 7 | CC7.1 | WAF logs, vulnerability scanner, IDS |
| T1110 | Brute Force | Credential Access | 🟡 Medium | AC-7, IA-5, AU-6 | A.5.17, A.8.5 | CIS 5.2, 6 | CC6.1 | Authentication failure logs, SIEM alerts |
| T1071.001 | Application Layer Protocol: Web Protocols (C2) | Command & Control | 🟠 High | SC-7, SC-44, SI-4 | A.8.20, A.8.22 | CIS 12, 13 | CC7.2 | Proxy logs, DNS logs, NTA/NDR |
| T1027 | Obfuscated Files or Information | Defense Evasion | 🟡 Medium | SI-3, CM-7, AU-12 | A.8.19, A.8.15 | CIS 10 | CC7.2 | EDR, script block logging |
| T1053.005 | Scheduled Task/Job | Persistence | 🟡 Medium | CM-7, AU-12, SI-7 | A.8.19, A.8.15 | CIS 4, 8 | CC6.1, CC7.2 | Windows Event 4698/4702, EDR |
| T1136 | Create Account | Persistence | 🟡 Medium | AC-2, AU-9, IA-2 | A.5.16, A.5.18 | CIS 5, 6 | CC6.2 | Directory change logs, SIEM |
| T1562.001 | Impair Defenses: Disable Security Tools | Defense Evasion | 🟠 High | AU-9, CM-7, SI-3 | A.8.19, A.8.15 | CIS 10 | CC7.2 | Security tool health monitoring, EDR |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | 🟠 High | SC-7, SC-44, DM policies | A.5.14, A.8.20 | CIS 12, 13 | CC6.7, CC7.2 | NDR, DLP, proxy/firewall logs |

**Prevalence Rating:** 🔴 Critical (seen in >50% of incidents) &nbsp;|&nbsp; 🟠 High (>25%) &nbsp;|&nbsp; 🟡 Medium (>10%) &nbsp;|&nbsp; 🔵 Low

---

## 🛡️ Ransomware Kill-Chain — Complete Control Mapping

```
RANSOMWARE ATTACK CHAIN                   GRC CONTROLS THAT BREAK EACH STAGE
═══════════════════════════════════════════════════════════════════════════════

STAGE 1: INITIAL ACCESS
  T1566 — Phishing Email               → Email filtering (CIS 9), Security Awareness (CIS 14)
  T1190 — Exploit Public App           → Vulnerability Management (CIS 7), WAF (SC-7)
  T1078 — Stolen Credentials           → MFA (CIS 5.3), PAM (CIS 5.4), UEBA

STAGE 2: EXECUTION & PERSISTENCE
  T1059 — Script Execution             → PowerShell constrained mode, script block logging
  T1053 — Scheduled Tasks              → Endpoint hardening (CIS 4), EDR detection
  T1547 — Boot/Logon Autostart         → Application allowlisting (CIS 2.7)

STAGE 3: PRIVILEGE ESCALATION
  T1055 — Process Injection            → EDR with behavioral detection, least privilege
  T1068 — Exploit Privilege Escalation → Patch management SLA (CIS 7.4)
  T1003 — Credential Dumping           → LSASS protection, Credential Guard, PAM

STAGE 4: LATERAL MOVEMENT
  T1021 — Remote Services              → Network segmentation (CIS 12), RDP restriction
  T1550 — Pass the Hash                → Disable NTLM, implement Kerberos, tier model
  T1563 — RDP Session Hijacking        → Just-in-time access, privileged workstations

STAGE 5: DATA STAGING & EXFILTRATION
  T1041 — Exfil over C2               → DLP (CIS 3.14), Proxy inspection, NDR
  T1048 — Exfil Alternative Protocol  → Egress filtering, DNS monitoring
  T1567 — Exfil to Cloud              → CASB, cloud app control, data classification

STAGE 6: IMPACT — ENCRYPTION
  T1486 — Data Encrypted for Impact   → Immutable backups (CIS 11), tested recovery
                                         File integrity monitoring, rapid IR plan
═══════════════════════════════════════════════════════════════════════════════
DEFENSE SUMMARY:
  Controls with highest kill-chain coverage:
  1. MFA + PAM                → Blocks Stages 1, 3, 4
  2. EDR with behavioral rules → Blocks Stages 2, 3, 4, 6
  3. Network Segmentation      → Degrades Stages 4, 5
  4. Immutable Backups         → Defeats Stage 6 (eliminates leverage)
  5. Patch Management SLA      → Reduces Stage 1, 3 attack surface
```

---

## 📊 Control Coverage Heat Map — Top 5 GRC Frameworks

| ATT&CK Tactic | NIST 800-53 | ISO 27001 | CIS v8 | SOC 2 TSC | Coverage Gap |
|:---|:---:|:---:|:---:|:---:|:---|
| Initial Access | ●●●●○ | ●●●○○ | ●●●●○ | ●●○○○ | SOC 2 lacks technical controls |
| Execution | ●●●●● | ●●●○○ | ●●●●○ | ●●●○○ | ISO 27001 high-level only |
| Persistence | ●●●●○ | ●●●○○ | ●●●●● | ●●○○○ | SOC 2 detection coverage weak |
| Privilege Escalation | ●●●●○ | ●●●○○ | ●●●●● | ●●●○○ | ISO 27001 lacks technical depth |
| Defense Evasion | ●●●○○ | ●●○○○ | ●●●●○ | ●●○○○ | All frameworks have gaps here |
| Credential Access | ●●●●● | ●●●○○ | ●●●●● | ●●●●○ | ISO 27001 less prescriptive |
| Lateral Movement | ●●●●○ | ●●●○○ | ●●●●○ | ●●●○○ | Needs network segmentation focus |
| Exfiltration | ●●●○○ | ●●●○○ | ●●●●○ | ●●●○○ | DLP coverage inconsistent |
| Impact | ●●●●● | ●●●●○ | ●●●●● | ●●●●○ | Strong coverage across all |

**Legend:** ● = Coverage strength (1–5 scale)

---

## 📚 References

- [MITRE ATT&CK Enterprise v15](https://attack.mitre.org/)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-53B Control Baselines](https://csrc.nist.gov/publications/detail/sp/800-53b/final)
- [Center for Threat-Informed Defense — ATT&CK to 800-53 Mapping](https://ctid.mitre-engenuity.org/)
- [CIS Controls v8](https://www.cisecurity.org/controls/v8)

---

## 📄 License

MIT License — free to use, adapt, and distribute with attribution.

---

<div align="center">
<i>Built by <a href="https://github.com/cyberzeshan">Zeshan Ahmad</a> · GRC Engineer & Cybersecurity SME</i>
</div>
