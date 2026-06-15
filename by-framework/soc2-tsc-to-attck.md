# SOC 2 TSC → MITRE ATT&CK Technique Mapping

**Purpose:** Maps each SOC 2 Trust Services Criteria (TSC) to the ATT&CK techniques it addresses. Use this when evaluating SOC 2 audit scope, understanding detection gaps in TSC-only environments, or advising clients on supplementing SOC 2 with threat-informed controls.

---

## Overview: SOC 2 TSC and ATT&CK Coverage Limitations

SOC 2 Trust Services Criteria are **outcome-oriented** rather than prescriptive. This gives auditees flexibility but results in broad ATT&CK coverage gaps — particularly for detection, evasion, and credential-based attacks. The TSC define *what* must be achieved, not *how*, leaving the technical implementation (and thus ATT&CK coverage) to each organization.

---

## CC1 — Control Environment

| TSC Criteria | Description | ATT&CK Relevance |
|:---|:---|:---|
| CC1.1–CC1.5 | Organizational structure, oversight, competence | Indirect — supports all tactics through governance |

**ATT&CK Coverage:** Minimal technical coverage. Sets the policy/governance foundation.

---

## CC2 — Communication and Information

| TSC Criteria | Description | ATT&CK Techniques Addressed |
|:---|:---|:---|
| CC2.2 | Communication of policies and procedures | T1566 (security awareness reduces phishing success), T1204 |
| CC2.3 | External communications | T1534, T1566.003 |

**ATT&CK Coverage:** Low — primarily awareness/policy layer.

---

## CC3 — Risk Assessment

| TSC Criteria | Description | ATT&CK Techniques Addressed |
|:---|:---|:---|
| CC3.1 | Risk identification | T1190, T1068 (risk-aware vulnerability management) |
| CC3.2 | Fraud risk assessment | T1078, T1036 (insider threat/fraud scenarios) |
| CC3.3 | Change in risk consideration | T1195 (supply chain risk) |
| CC3.4 | Risk identification with third parties | T1195 |

---

## CC4 — Monitoring Activities

| TSC Criteria | Description | ATT&CK Techniques Addressed |
|:---|:---|:---|
| CC4.1 | Ongoing and/or separate evaluations | T1110, T1078, T1041 (anomaly detection) |
| CC4.2 | Evaluating and communicating deficiencies | T1562.001 (impaired defenses detection) |

---

## CC5 — Control Activities

| TSC Criteria | Description | ATT&CK Techniques Addressed |
|:---|:---|:---|
| CC5.1 | Controls selected and implemented to mitigate risk | General baseline |
| CC5.2 | Technology controls | T1059, T1078 (technology-based controls) |
| CC5.3 | Controls deployed through policies | T1566 (policy controls) |

---

## CC6 — Logical and Physical Access Controls *(Highest ATT&CK Coverage)*

| TSC Criteria | Description | ATT&CK Techniques Addressed | Coverage |
|:---|:---|:---|:---:|
| CC6.1 | Logical access security | T1078, T1110, T1003, T1558, T1555 | ●●●●○ |
| CC6.2 | Authentication and access provisioning | T1136, T1098, T1078.002 | ●●●○○ |
| CC6.3 | Remove/restrict access when no longer needed | T1078, T1530 | ●●●○○ |
| CC6.4 | Physical access | T1091 | ●●○○○ |
| CC6.6 | Logical access from outside the entity's network | T1021, T1133, T1563 | ●●●○○ |
| CC6.7 | Transmission and movement of information | T1041, T1048, T1567 | ●●●○○ |
| CC6.8 | Malicious software prevention | T1059, T1055, T1027, T1486 | ●●●○○ |

**CC6 is the most ATT&CK-relevant TSC category.** CC6.1 covers credential-based attacks; CC6.6 addresses remote access vectors; CC6.7 addresses exfiltration; CC6.8 covers malware execution.

---

## CC7 — System Operations *(Second-Highest ATT&CK Coverage)*

| TSC Criteria | Description | ATT&CK Techniques Addressed | Coverage |
|:---|:---|:---|:---:|
| CC7.1 | Detect and monitor for vulnerabilities | T1190, T1068, T1210 | ●●●○○ |
| CC7.2 | Monitor system components for anomalous behavior | T1059, T1055, T1027, T1562, T1003, T1041 | ●●●●○ |
| CC7.3 | Evaluate security events | T1078, T1110, T1041 | ●●●○○ |
| CC7.4 | Respond to security incidents | T1486 (IR readiness) | ●●●○○ |
| CC7.5 | Identify and disclose breaches | T1486, T1491 | ●●○○○ |

**CC7.2** is the key detection criteria — it requires anomaly monitoring, which maps to detection of T1059 (execution), T1003 (credential dumping), T1041 (exfil), and T1562 (defense impairment).

---

## CC8 — Change Management

| TSC Criteria | Description | ATT&CK Techniques Addressed |
|:---|:---|:---|
| CC8.1 | Authorize, design, develop, acquire, configure, document, test, approve, and implement changes | T1195.002 (supply chain compromise in dev) |

---

## CC9 — Risk Mitigation

| TSC Criteria | Description | ATT&CK Techniques Addressed |
|:---|:---|:---|
| CC9.1 | Identify, select, and develop risk mitigation activities | General |
| CC9.2 | Monitor selected vendor/business partner risks | T1195 (supply chain) |

---

## A-Series — Availability

| TSC Criteria | Description | ATT&CK Techniques Addressed | Coverage |
|:---|:---|:---|:---:|
| A1.1 | Capacity management | T1499 (DoS) | ●●●○○ |
| A1.2 | Recovery commitments | T1486, T1561, T1490 | ●●●●○ |
| A1.3 | Environmental protections | Physical threats | ●●○○○ |

---

## C-Series — Confidentiality

| TSC Criteria | Description | ATT&CK Techniques Addressed |
|:---|:---|:---|
| C1.1 | Identify/maintain confidential information | T1005, T1039 |
| C1.2 | Dispose/destroy confidential information | T1025, T1485 |

---

## PI-Series — Processing Integrity

Limited direct ATT&CK mapping — focused on data accuracy and completeness rather than security techniques.

---

## SOC 2 ATT&CK Coverage Gap Analysis

### Techniques Poorly Addressed by TSC

| ATT&CK Technique | Why TSC Falls Short | Recommended Supplement |
|:---|:---|:---|
| T1070 (Indicator Removal) | No explicit log protection requirements | NIST AU-9, CIS 8.9 |
| T1053 (Scheduled Tasks) | CC7.2 anomaly detection covers it loosely | NIST CM-7, CIS 4.1 |
| T1562 (Impair Defenses) | CC6.8 malware protection partial | NIST AU-9, CIS 10.6 |
| T1055 (Process Injection) | CC6.8 covers malware broadly | NIST SI-3, SC-39, CIS 10.5 |
| T1558 (Kerberos Tickets) | No AD-specific controls in TSC | NIST IA-5, CIS 5.4 |
| T1195 (Supply Chain) | CC9.2 is policy-level only | NIST SR-3/SR-4, CIS 2.5 |
| T1218 (LOLBins) | CC6.8 may not capture these | NIST CM-7, CIS 2.7 |

### SOC 2 Coverage Heat Map

| ATT&CK Tactic | TSC Coverage | Key Gap |
|:---|:---:|:---|
| Initial Access | ●●○○○ | CC6.1 covers credentials; phishing/vuln exploitation weak |
| Execution | ●●○○○ | CC6.8 covers malware broadly; scripting/LOLBins not addressed |
| Persistence | ●●○○○ | CC7.2 may detect anomalies; no explicit persistence controls |
| Privilege Escalation | ●●●○○ | CC6.1 covers access; technical escalation techniques not prescriptive |
| Defense Evasion | ●●○○○ | Weakest TSC coverage area |
| Credential Access | ●●●○○ | CC6.1 prevents unauthorized access; no credential-specific tech controls |
| Lateral Movement | ●●●○○ | CC6.6 covers remote access; internal lateral movement limited |
| Exfiltration | ●●●○○ | CC6.7 covers data transfer controls |
| Impact | ●●●●○ | A1.2 (availability/recovery) + CC7.4/7.5 strong for incident response |

---

## Recommendation: SOC 2 + Supplemental Framework

For organizations relying on SOC 2 as their primary GRC framework, recommend layering:

| Threat Area | TSC Criteria | Supplement With |
|:---|:---|:---|
| Ransomware defense | A1.2, CC7.4 | NIST CP-9/CP-10 for backup specifics |
| Credential protection | CC6.1 | NIST IA-5, CIS 5.4 for technical controls |
| Detection capability | CC7.2 | CIS 8 (audit logs), CIS 13 (network monitoring) |
| Vulnerability management | CC7.1 | CIS 7, NIST RA-5 for scanning rigor |
| Configuration hardening | CC5.2 | NIST CM-7, CIS 4 for endpoint hardening |
