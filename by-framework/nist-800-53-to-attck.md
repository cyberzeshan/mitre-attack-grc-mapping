# NIST SP 800-53 Rev 5 → MITRE ATT&CK Technique Mapping

**Purpose:** For each NIST control family, identifies which ATT&CK techniques it helps detect, prevent, or respond to. Use this view when performing control assessments to understand your threat coverage posture.

---

## AC — Access Control

| NIST Control | Control Name | ATT&CK Techniques Mitigated | Coverage Strength |
|:---|:---|:---|:---:|
| AC-2 | Account Management | T1078, T1136, T1098 | ●●●●○ |
| AC-3 | Access Enforcement | T1078, T1550, T1558, T1003.006 | ●●●●○ |
| AC-6 | Least Privilege | T1055, T1548, T1134, T1003, T1021 | ●●●●● |
| AC-7 | Unsuccessful Login Attempts | T1110 | ●●●●○ |
| AC-17 | Remote Access | T1021, T1133 | ●●●●○ |
| AC-22 | Publicly Accessible Content | T1567 | ●●●○○ |

**Key Insight:** AC-6 (Least Privilege) is the single highest-value control in this family — it directly reduces the effectiveness of privilege escalation, lateral movement, and credential access techniques.

---

## AT — Awareness and Training

| NIST Control | Control Name | ATT&CK Techniques Mitigated | Coverage Strength |
|:---|:---|:---|:---:|
| AT-2 | Literacy Training and Awareness | T1566, T1534, T1204 | ●●●○○ |
| AT-3 | Role-Based Training | T1566.001, T1566.004 | ●●●○○ |

**Key Insight:** AT controls are essential for social engineering mitigations but provide no technical prevention. Pair with SI-8 (spam protection) and CM-7 (configuration restrictions).

---

## AU — Audit and Accountability

| NIST Control | Control Name | ATT&CK Techniques Mitigated | Coverage Strength |
|:---|:---|:---|:---:|
| AU-6 | Audit Record Review | T1110, T1078, T1021 | ●●●○○ |
| AU-9 | Protection of Audit Information | T1070, T1562.002 | ●●●●○ |
| AU-12 | Audit Record Generation | T1053, T1543, T1070, T1136, T1098 | ●●●●○ |

**Key Insight:** AU-9 is critical — if attackers can delete logs, the entire audit capability fails. Central log forwarding (SIEM) is the implementation that makes AU-9 effective against T1070.

---

## CM — Configuration Management

| NIST Control | Control Name | ATT&CK Techniques Mitigated | Coverage Strength |
|:---|:---|:---|:---:|
| CM-6 | Configuration Settings | T1548, T1543, T1547, T1110 | ●●●●○ |
| CM-7 | Least Functionality | T1059, T1027, T1218, T1036, T1562, T1021 | ●●●●● |
| CM-14 | Signed Components | T1195, T1027.004 | ●●●○○ |

**Key Insight:** CM-7 (Least Functionality) is arguably the most broadly effective NIST control — disabling unnecessary services, interpreters, and features removes entire attack surface areas.

---

## CP — Contingency Planning

| NIST Control | Control Name | ATT&CK Techniques Mitigated | Coverage Strength |
|:---|:---|:---|:---:|
| CP-9 | System Backup | T1486, T1485, T1490, T1561 | ●●●●● |
| CP-10 | System Recovery and Reconstitution | T1486, T1561 | ●●●●○ |

**Key Insight:** CP-9 is the last line of defense against ransomware. Immutable, air-gapped, tested backups completely neutralize the leverage of T1486 (Data Encrypted for Impact).

---

## IA — Identification and Authentication

| NIST Control | Control Name | ATT&CK Techniques Mitigated | Coverage Strength |
|:---|:---|:---|:---:|
| IA-2 | Identification and Authentication (Org Users) | T1078, T1110, T1550 | ●●●●● |
| IA-5 | Authenticator Management | T1003, T1110, T1558, T1555 | ●●●●● |

**Key Insight:** IA-2 + IA-5 together (MFA + strong credentials) are the highest-ROI NIST controls for preventing unauthorized access. They block PtH, brute force, and credential stuffing.

---

## IR — Incident Response

| NIST Control | Control Name | ATT&CK Techniques Mitigated | Coverage Strength |
|:---|:---|:---|:---:|
| IR-4 | Incident Handling | T1486, T1485, T1491, T1499 | ●●●○○ |
| IR-6 | Incident Reporting | T1486 (response phase) | ●●○○○ |

---

## RA — Risk Assessment

| NIST Control | Control Name | ATT&CK Techniques Mitigated | Coverage Strength |
|:---|:---|:---|:---:|
| RA-3 | Risk Assessment | T1190, T1068 (risk awareness) | ●●○○○ |
| RA-5 | Vulnerability Monitoring and Scanning | T1190, T1068, T1210 | ●●●●○ |

---

## SC — System and Communications Protection

| NIST Control | Control Name | ATT&CK Techniques Mitigated | Coverage Strength |
|:---|:---|:---|:---:|
| SC-5 | Denial of Service Protection | T1499 | ●●●○○ |
| SC-7 | Boundary Protection | T1041, T1048, T1071, T1021, T1133 | ●●●●● |
| SC-8 | Transmission Confidentiality/Integrity | T1048, T1040, T1557 | ●●●○○ |
| SC-28 | Protection of Information at Rest | T1003, T1555, T1550 | ●●●○○ |
| SC-39 | Process Isolation | T1055, T1068 | ●●●○○ |
| SC-44 | Detonation Chambers | T1041, T1566 | ●●●○○ |

**Key Insight:** SC-7 (Boundary Protection) provides the broadest coverage for command-and-control and exfiltration techniques. Combined with egress filtering and proxy inspection, it breaks multiple kill-chain stages.

---

## SI — System and Information Integrity

| NIST Control | Control Name | ATT&CK Techniques Mitigated | Coverage Strength |
|:---|:---|:---|:---:|
| SI-2 | Flaw Remediation | T1190, T1068, T1210 | ●●●●○ |
| SI-3 | Malicious Code Protection | T1059, T1027, T1055, T1486 | ●●●●● |
| SI-4 | System Monitoring | T1041, T1071, T1048, T1110 | ●●●●○ |
| SI-7 | Software, Firmware, and Information Integrity | T1036, T1070, T1543 | ●●●○○ |
| SI-8 | Spam Protection | T1566, T1534 | ●●●●○ |

---

## SR — Supply Chain Risk Management

| NIST Control | Control Name | ATT&CK Techniques Mitigated | Coverage Strength |
|:---|:---|:---|:---:|
| SR-3 | Supply Chain Controls and Processes | T1195 | ●●●○○ |
| SR-4 | Provenance | T1195.001, T1195.002 | ●●●○○ |

---

## Top 10 NIST Controls by ATT&CK Coverage Breadth

| Rank | Control | Techniques Covered | Key Tactic Areas |
|:---:|:---|:---:|:---|
| 1 | CM-7 Least Functionality | 15+ | Execution, Evasion, Lateral Movement |
| 2 | SC-7 Boundary Protection | 12+ | C2, Exfiltration, Initial Access |
| 3 | SI-3 Malicious Code Protection | 10+ | Execution, Evasion, Impact |
| 4 | AC-6 Least Privilege | 10+ | Priv Escalation, Lateral Movement, Cred Access |
| 5 | IA-2 MFA | 8+ | Initial Access, Lateral Movement, Persistence |
| 6 | AU-12 Audit Record Generation | 8+ | Persistence, Defense Evasion, Cred Access |
| 7 | CP-9 System Backup | 5 | Impact (ransomware defense) |
| 8 | RA-5 Vulnerability Scanning | 5 | Initial Access, Privilege Escalation |
| 9 | SI-4 System Monitoring | 5+ | Exfiltration, C2, Credential Access |
| 10 | IA-5 Authenticator Management | 5+ | Credential Access, Lateral Movement |
