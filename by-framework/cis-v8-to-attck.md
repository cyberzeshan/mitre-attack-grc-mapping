# CIS Controls v8 → MITRE ATT&CK Technique Mapping

**Purpose:** Maps each CIS Control v8 (and key sub-controls) to ATT&CK techniques. CIS Controls are Implementation Group (IG) tiered — IG1 for all organizations, IG2 for mid-sized, IG3 for large/sensitive. ATT&CK coverage increases significantly at IG2+.

---

## Control 1 — Inventory and Control of Enterprise Assets

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 1.1 | Establish and Maintain Detailed Enterprise Asset Inventory | T1195.003, T1018 (discovery) | IG1 |
| 1.2 | Address Unauthorized Assets | T1200, T1091 | IG1 |
| 1.6 | Address Unauthorized Mobile Devices | T1091, T1200 | IG2 |

---

## Control 2 — Inventory and Control of Software Assets

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 2.5 | Allowlist Authorized Software | T1195.001, T1036, T1027 | IG2 |
| 2.6 | Allowlist Authorized Libraries | T1055, T1574 | IG2 |
| 2.7 | Allowlist Authorized Scripts | T1059, T1218, T1027, T1036 | IG2 |

**Key Insight:** CIS 2.7 (script allowlisting) is one of the most powerful controls — implementing it via WDAC/AppLocker blocks the majority of LOLBin and obfuscated script execution techniques.

---

## Control 3 — Data Protection

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 3.3 | Configure Data Access Control Lists | T1078, T1005, T1074 | IG1 |
| 3.11 | Encrypt Sensitive Data at Rest | T1003, T1555, T1552 | IG1 |
| 3.14 | Log Sensitive Data Access | T1005, T1039, T1567 | IG2 |

---

## Control 4 — Secure Configuration of Enterprise Assets and Software

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 4.1 | Establish and Maintain a Secure Config Process | T1543, T1547, T1053 | IG1 |
| 4.5 | Implement and Manage a Firewall on Servers | T1021, T1133, T1571 | IG1 |
| 4.6 | Implement and Manage a Firewall on Endpoints | T1021.001, T1041 | IG2 |
| 4.7 | Manage Default Accounts | T1078.001 | IG1 |
| 4.8 | Uninstall or Disable Unnecessary Services | T1543, T1133 | IG2 |

---

## Control 5 — Account Management

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 5.1 | Establish and Maintain an Inventory of Accounts | T1078, T1136 | IG1 |
| 5.2 | Use Unique Passwords | T1110.001, T1110.003, T1110.004 | IG1 |
| 5.3 | Disable Dormant Accounts | T1078 | IG1 |
| 5.4 | Restrict Administrator Privileges | T1003, T1055, T1548, T1558, T1134 | IG1 |
| 5.5 | Establish and Maintain an Inventory of Service and Application Accounts | T1098, T1555.006 | IG2 |

**Key Insight:** CIS 5.4 (Restrict Admin Privileges) has the widest ATT&CK impact of any single CIS sub-control — it directly constrains credential dumping (T1003), process injection (T1055), privilege escalation (T1548), and Kerberos attacks (T1558).

---

## Control 6 — Access Control Management

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 6.1 | Establish an Access Granting Process | T1078, T1136, T1098 | IG1 |
| 6.2 | Establish an Access Revoking Process | T1136, T1098 | IG1 |
| 6.3 | Require MFA for Externally-Exposed Applications | T1078, T1110, T1133 | IG1 |
| 6.4 | Require MFA for Remote Network Access | T1133, T1021 | IG1 |
| 6.5 | Require MFA for Administrative Access | T1078.002, T1548 | IG2 |
| 6.7 | Centralize Access Control | T1078, T1110 | IG2 |
| 6.8 | Define and Maintain Role-Based Access Control | T1098.003 | IG3 |

---

## Control 7 — Continuous Vulnerability Management

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 7.1 | Establish and Maintain a Vulnerability Management Process | T1190, T1068 | IG1 |
| 7.4 | Perform Automated Application Vulnerability Scans | T1190, T1210 | IG2 |
| 7.5 | Perform Automated Vulnerability Scans of Internal Enterprise Assets | T1068, T1210 | IG2 |
| 7.6 | Perform Automated Vulnerability Scans of Externally-Exposed Assets | T1190 | IG2 |
| 7.7 | Remediate Detected Vulnerabilities | T1190, T1068, T1210 | IG2 |

---

## Control 8 — Audit Log Management

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 8.1 | Establish and Maintain an Audit Log Management Process | T1070, T1562.002 | IG1 |
| 8.2 | Collect Audit Logs | T1070, T1053, T1543, T1136 | IG1 |
| 8.3 | Ensure Adequate Audit Log Storage | T1070.001, T1562.002 | IG1 |
| 8.5 | Collect Detailed Audit Logs | T1070.006, T1562.006 | IG2 |
| 8.9 | Centralize Audit Logs | T1070, T1562.002 | IG2 |
| 8.11 | Conduct Audit Log Reviews | T1110, T1078 | IG2 |

---

## Control 9 — Email and Web Browser Protections

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 9.2 | Use DNS Filtering Services | T1566.002, T1071.004 | IG1 |
| 9.3 | Maintain and Enforce Network-Based URL Filters | T1566.002, T1567.003 | IG2 |
| 9.4 | Restrict Unnecessary or Unauthorized Browser/Email Extensions | T1176 | IG2 |
| 9.5 | Implement DMARC | T1566.001 (spoofing prevention) | IG1 |
| 9.6 | Block Unnecessary File Types | T1566.001 | IG2 |

---

## Control 10 — Malware Defenses

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 10.1 | Deploy and Maintain Anti-Malware Software | T1059, T1055, T1027, T1036 | IG1 |
| 10.2 | Configure Automatic Anti-Malware Signature Updates | T1562.001 (AV bypass) | IG1 |
| 10.5 | Enable Anti-Exploitation Features | T1068, T1055 | IG2 |
| 10.6 | Centrally Manage Anti-Malware Software | T1562.001 | IG2 |
| 10.7 | Use Behavior-Based Anti-Malware Software | T1486, T1059, T1055 | IG2 |

---

## Control 11 — Data Recovery

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 11.1 | Establish and Maintain a Data Recovery Process | T1486, T1485 | IG1 |
| 11.2 | Perform Automated Backups | T1485, T1561 | IG1 |
| 11.3 | Protect Recovery Data | T1490 | IG1 |
| 11.4 | Establish and Maintain an Isolated Instance of Recovery Data | T1486, T1490 | IG2 |
| 11.5 | Test Data Recovery | T1486 (resilience) | IG2 |

---

## Control 12 — Network Infrastructure Management

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 12.2 | Establish and Maintain a Secure Network Architecture | T1021, T1041, T1071 | IG2 |
| 12.3 | Securely Manage Network Infrastructure | T1021.001 (RDP) | IG1 |
| 12.6 | Use of Secure Network Management and Communication Protocols | T1048, T1040 | IG2 |
| 12.8 | Establish and Maintain Dedicated Computing Resources for Admin Activities | T1550, T1021 | IG3 |

---

## Control 13 — Network Monitoring and Defense

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 13.1 | Centralize Security Event Alerting | T1110, T1041, T1071 | IG2 |
| 13.2 | Deploy a Host-Based Intrusion Detection Solution | T1055, T1003, T1059 | IG2 |
| 13.3 | Deploy a Network Intrusion Detection Solution | T1041, T1071, T1048 | IG2 |
| 13.8 | Deploy a Network Intrusion Prevention Solution | T1071.001, T1041 | IG3 |
| 13.9 | Deploy Port-Level Access Control | T1048, T1041 | IG2 |

---

## Control 14 — Security Awareness and Skills Training

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 14.2 | Train Workforce Members to Recognize Social Engineering Attacks | T1566, T1534 | IG1 |
| 14.9 | Conduct Role-Specific Security Awareness and Skills Training | T1566.004 | IG2 |

---

## Control 16 — Application Software Security

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 16.2 | Establish and Maintain a Process to Accept and Address Software Vulnerabilities | T1195.001 | IG2 |

---

## Control 17 — Incident Response Management

| CIS Sub-Control | Description | ATT&CK Techniques Addressed | IG |
|:---|:---|:---|:---:|
| 17.1–17.9 | Full IR lifecycle | T1486, T1485, T1491, T1499 | IG1–IG3 |

---

## Implementation Group Coverage Summary

| Implementation Group | ATT&CK Technique Coverage | Recommended For |
|:---|:---:|:---|
| IG1 (56 safeguards) | ~40% of top techniques | All organizations |
| IG2 (130 safeguards) | ~70% of top techniques | Mid-sized organizations |
| IG3 (153 safeguards) | ~90% of top techniques | Sensitive/regulated organizations |
