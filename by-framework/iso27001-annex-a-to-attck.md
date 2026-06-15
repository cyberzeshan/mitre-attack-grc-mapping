# ISO 27001:2022 Annex A → MITRE ATT&CK Technique Mapping

**Purpose:** Maps each ISO 27001:2022 Annex A control to the ATT&CK techniques it addresses. Use this when conducting ISO 27001 gap assessments or SoA (Statement of Applicability) reviews to understand threat-informed coverage.

---

## 5 — Organizational Controls

| Annex A Control | Control Name | ATT&CK Techniques Covered | Coverage |
|:---|:---|:---|:---:|
| A.5.1 | Policies for Information Security | General baseline | ●●○○○ |
| A.5.7 | Threat Intelligence | All tactics (informed defense) | ●●○○○ |
| A.5.8 | Information Security in Project Management | T1195 (supply chain) | ●●○○○ |
| A.5.10 | Acceptable Use of Information | T1078, T1567 | ●●○○○ |
| A.5.14 | Information Transfer | T1041, T1048, T1567, T1020 | ●●●○○ |
| A.5.15 | Access Control | T1078, T1098, T1550 | ●●●○○ |
| A.5.16 | Identity Management | T1136, T1078.001, T1098 | ●●●○○ |
| A.5.17 | Authentication Information | T1003, T1110, T1558, T1555 | ●●●●○ |
| A.5.18 | Access Rights | T1078, T1136, T1098, T1134 | ●●●○○ |
| A.5.19 | Information Security in Supplier Relationships | T1195 | ●●●○○ |
| A.5.20 | Addressing Security in Supplier Agreements | T1195 | ●●○○○ |
| A.5.24 | Information Security Incident Management Planning | T1486 (IR readiness) | ●●○○○ |
| A.5.29 | Information Security during Disruption | T1486, T1485, T1499 | ●●●○○ |
| A.5.30 | ICT Readiness for Business Continuity | T1486, T1561 | ●●●○○ |

**Key Insight:** ISO 27001:2022 Organizational controls are primarily policy and governance — they create the framework but rely on technical controls in sections 8 and below for ATT&CK coverage.

---

## 6 — People Controls

| Annex A Control | Control Name | ATT&CK Techniques Covered | Coverage |
|:---|:---|:---|:---:|
| A.6.3 | Information Security Awareness, Education, Training | T1566, T1534, T1204 | ●●●○○ |
| A.6.7 | Remote Working | T1021, T1133, T1563 | ●●●○○ |
| A.6.8 | Information Security Event Reporting | All detection-related | ●●○○○ |

---

## 7 — Physical Controls

| Annex A Control | Control Name | ATT&CK Techniques Covered | Coverage |
|:---|:---|:---|:---:|
| A.7.10 | Storage Media | T1485, T1561, T1025 | ●●○○○ |

---

## 8 — Technological Controls

| Annex A Control | Control Name | ATT&CK Techniques Covered | Coverage |
|:---|:---|:---|:---:|
| A.8.2 | Privileged Access Rights | T1078.002, T1134, T1548, T1003 | ●●●●○ |
| A.8.3 | Information Access Restriction | T1078, T1550 | ●●●○○ |
| A.8.5 | Secure Authentication | T1003, T1110, T1558, T1078 | ●●●●○ |
| A.8.6 | Capacity Management | T1499 | ●●○○○ |
| A.8.7 | Protection Against Malware | T1059, T1055, T1027, T1486 | ●●●●○ |
| A.8.8 | Management of Technical Vulnerabilities | T1190, T1068, T1210, T1055 | ●●●●○ |
| A.8.9 | Configuration Management | T1543, T1547, T1053 | ●●●○○ |
| A.8.13 | Information Backup | T1486, T1485, T1490, T1561 | ●●●●● |
| A.8.15 | Logging | T1070, T1562.002, T1053, T1543 | ●●●●○ |
| A.8.16 | Monitoring Activities | T1110, T1041, T1071 | ●●●○○ |
| A.8.18 | Use of Privileged Utility Programs | T1548.001, T1548.003 | ●●●○○ |
| A.8.19 | Installation of Software on Operational Systems | T1059, T1053, T1543, T1027, T1036, T1218, T1562 | ●●●●○ |
| A.8.20 | Network Security | T1021, T1041, T1048, T1071, T1133 | ●●●●○ |
| A.8.22 | Segregation of Networks | T1021, T1041 | ●●●○○ |
| A.8.23 | Web Filtering | T1566.001/002, T1071.001 | ●●●○○ |
| A.8.25 | Secure Development Life Cycle | T1190, T1195.002 | ●●●○○ |
| A.8.26 | Application Security Requirements | T1190, T1059 | ●●●○○ |
| A.8.28 | Secure Coding | T1190, T1059 | ●●●○○ |
| A.8.29 | Security Testing in Development and Acceptance | T1190 | ●●○○○ |
| A.8.30 | Outsourced Development | T1195 | ●●○○○ |

---

## Coverage Analysis by ATT&CK Tactic

| ATT&CK Tactic | Primary Annex A Controls | Overall Coverage |
|:---|:---|:---:|
| Initial Access | A.8.23, A.6.3, A.8.8, A.8.20 | ●●●○○ |
| Execution | A.8.7, A.8.19, A.8.26 | ●●●○○ |
| Persistence | A.8.9, A.8.15, A.8.19 | ●●●○○ |
| Privilege Escalation | A.8.2, A.8.8, A.5.18 | ●●●○○ |
| Defense Evasion | A.8.15, A.8.19, A.8.7 | ●●○○○ |
| Credential Access | A.5.17, A.8.5, A.8.2 | ●●●○○ |
| Lateral Movement | A.8.20, A.8.22, A.6.7 | ●●●○○ |
| Exfiltration | A.5.14, A.8.20, A.8.13 | ●●●○○ |
| Impact | A.8.13, A.5.29, A.5.30 | ●●●●○ |

---

## ISO 27001 vs NIST 800-53: Coverage Gap Analysis

| ATT&CK Area | ISO 27001 Gap | NIST Equivalent |
|:---|:---|:---|
| Log tampering (T1070) | A.8.15 is high-level; lacks centralized forwarding requirement | AU-9 explicitly protects audit records |
| Process injection (T1055) | A.8.7/8.8 don't address memory protection | SC-39 (Process Isolation) fills this gap |
| Supply chain (T1195) | A.5.19/5.20 cover policy; weak on technical SBOM requirements | SR-3/SR-4 more specific |
| LOLBins/execution (T1218) | A.8.19 doesn't enumerate prohibited tools | CM-7 allows specific feature removal mandates |
| Network C2 (T1071) | A.8.20 covers network security broadly | SC-7, SC-44 more specific for C2 detection |

---

## Statement of Applicability (SoA) Threat-Informed Prioritization

Controls that provide the **highest ATT&CK coverage** and should always be marked applicable:

1. **A.8.13** (Backup) — neutralizes T1486 ransomware
2. **A.8.7** (Anti-malware) — blocks T1059, T1055, T1486 execution
3. **A.5.17** (Authentication Info) — prevents T1003, T1110, T1558
4. **A.8.20** (Network Security) — disrupts T1041, T1071, T1021
5. **A.8.8** (Vulnerability Management) — closes T1190, T1068 entry points
6. **A.8.2** (Privileged Access Rights) — contains T1134, T1548, T1078
7. **A.6.3** (Security Awareness) — reduces T1566 phishing success rate
8. **A.8.15** (Logging) — enables detection of T1070, T1053, T1543
