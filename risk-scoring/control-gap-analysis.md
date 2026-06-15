# Control Gap Analysis — ATT&CK Coverage Gaps by Framework

**Purpose:** Identifies where GRC control frameworks leave ATT&CK techniques uncovered or weakly covered. Use this during gap assessments, SOC 2 readiness reviews, or NIST RMF implementations to understand residual threat exposure.

---

## How to Read This Document

A **gap** exists when:
1. A technique has **prevalence ≥ High** AND
2. No framework control provides **strong technical mitigation** for it

Gaps are categorized:
- 🔴 **Critical Gap** — High-prevalence technique with no adequate control in the framework
- 🟠 **Significant Gap** — High-prevalence technique with only policy-level (not technical) control
- 🟡 **Moderate Gap** — Medium-prevalence technique with weak coverage

---

## Framework-by-Framework Gap Analysis

### NIST SP 800-53 Rev 5 — Gap Analysis

| ATT&CK Technique | Gap Type | Missing Control | Root Cause |
|:---|:---:|:---|:---|
| T1071.001 (Web Protocol C2) | 🟡 | SC-44 exists but DNS tunneling coverage weak | NIST lacks specific DNS monitoring control |
| T1195.001 (Software Supply Chain) | 🟠 | SR-3/SR-4 present but SBOM not mandated | Supply chain controls newly added, adoption lag |
| T1558.003 (Kerberoasting) | 🟡 | IA-5 covers passwords broadly; no Kerberos-specific | NIST doesn't specify Kerberos AES enforcement |
| T1567.004 (Exfil to GenAI) | 🔴 | No control exists for AI data exfiltration | Emerging vector; Rev 5 predates GenAI risk |
| T1566.004 (Vishing) | 🟠 | AT-2/AT-3 cover awareness; no technical control | Voice-based attacks require human control only |

**NIST Coverage Score: 82% of top 25 techniques**

**Top NIST Gaps to Address:**
1. Add DNS monitoring policy as SC-7 enhancement
2. Implement SBOM requirements via SR-3 control enhancements
3. Document GenAI data handling in DM policy (emerging)

---

### ISO 27001:2022 Annex A — Gap Analysis

| ATT&CK Technique | Gap Type | Missing Control | Root Cause |
|:---|:---:|:---|:---|
| T1070 (Indicator Removal) | 🔴 | A.8.15 covers logging but not log tamper prevention | No equivalent to NIST AU-9 |
| T1055 (Process Injection) | 🟠 | A.8.7 covers anti-malware; memory protection not addressed | ISO doesn't prescribe kernel-level protections |
| T1053 (Scheduled Tasks) | 🟠 | A.8.9 covers config; no task scheduling specifics | High-level config management control |
| T1218 (LOLBins) | 🔴 | No control for legitimate tool abuse | ISO framework doesn't enumerate prohibited tools |
| T1558 (Kerberos Attacks) | 🔴 | A.5.17 covers credentials generally; no AD specifics | AD-specific guidance absent from ISO Annex A |
| T1195 (Supply Chain) | 🟠 | A.5.19/5.20 policy-level; no technical SBOM/scanning | Supplier controls are contractual, not technical |
| T1059.001 (PowerShell) | 🟠 | A.8.19 covers software installation; not scripting | No script allowlisting equivalent |

**ISO 27001:2022 Coverage Score: 61% of top 25 techniques**

**Top ISO Gaps to Address:**
1. Supplement Annex A with NIST AU-9 equivalent (centralized tamper-proof logging)
2. Add Annex A implementation note for application allowlisting under A.8.19
3. Explicitly scope AD security hardening under A.8.2/5.17
4. Add SBOM/SCA requirements as A.5.19 implementation guidance

---

### CIS Controls v8 — Gap Analysis

| ATT&CK Technique | Gap Type | Missing Control | Root Cause |
|:---|:---:|:---|:---|
| T1558.001 (Golden Ticket) | 🟠 | CIS 5.4 covers admin restriction; AD-specific guidance sparse | No CIS control specifically addresses Kerberos attacks |
| T1195.003 (Hardware Supply Chain) | 🟡 | CIS 1.1 asset inventory is weak prevention | Hardware supply chain is out-of-band |
| T1499 (DoS) | 🟡 | CIS 12 covers network; no DDoS/resilience controls | CIS focused on endpoint/identity, not availability |
| T1134 (Token Manipulation) | 🟠 | CIS 5.4 covers privilege restriction; API-level token attacks not addressed | No Windows token manipulation specific control |

**CIS Controls v8 Coverage Score: 88% of top 25 techniques**

CIS v8 has the **best ATT&CK coverage** of the four frameworks due to its technical prescriptiveness. Remaining gaps are primarily in AD-specific attacks and availability-focused techniques.

---

### SOC 2 TSC — Gap Analysis

| ATT&CK Technique | Gap Type | Missing Control | Root Cause |
|:---|:---:|:---|:---|
| T1070 (Indicator Removal) | 🔴 | No log protection criteria | TSC doesn't mandate centralized/immutable logging |
| T1053 (Scheduled Tasks) | 🔴 | CC7.2 anomaly detection loosely applicable | No persistence-specific detection control |
| T1562.001 (Disable Security Tools) | 🔴 | CC6.8 malware prevention; tool tamper protection absent | TSC outcome-oriented, not preventive on this technique |
| T1055 (Process Injection) | 🔴 | CC6.8 covers malware broadly; injection-specific absent | No kernel-level or EDR mandate in TSC |
| T1218 (LOLBins) | 🔴 | Not addressed by any TSC criteria | Significant coverage gap |
| T1558 (Kerberos Attacks) | 🔴 | CC6.1 covers access control; no AD/Kerberos specifics | Domain-level attack techniques outside TSC scope |
| T1021 (Lateral Movement via RDP) | 🟠 | CC6.6 covers remote access; workstation-to-workstation lateral not addressed | TSC focuses on external access |
| T1195 (Supply Chain) | 🟠 | CC9.2 covers vendor monitoring; no technical SBOM requirement | Policy/vendor management focus |

**SOC 2 TSC Coverage Score: 45% of top 25 techniques**

SOC 2 has the **most significant ATT&CK gaps** — organizations relying solely on SOC 2 should layer at minimum CIS IG2 controls.

---

## Universal Gaps — All Frameworks

These techniques are **underaddressed across all four frameworks**:

| ATT&CK Technique | Gap Description | Recommended Supplement |
|:---|:---|:---|
| T1567.004 (GenAI Exfiltration) | All frameworks predate widespread GenAI risk | CASB, data classification + DLP for AI endpoints |
| T1195.001 (Software Dependencies) | SBOM requirements emerging; adoption low | Mandatory SCA in CI/CD; NIST SSDF (SP 800-218) |
| T1558.003 (Kerberoasting) | AD-specific; frameworks stay high-level | CIS Benchmark for Windows Server, tiered AD model |
| T1071.004 (DNS as C2) | DNS monitoring underspecified everywhere | DNS RPZ, passive DNS, DNS-over-HTTPS inspection |

---

## Control Gap Heatmap

```
FRAMEWORK COVERAGE BY ATT&CK TACTIC
═════════════════════════════════════════════════════════════════════

Tactic              NIST 800-53    ISO 27001    CIS v8    SOC 2 TSC
─────────────────────────────────────────────────────────────────────
Initial Access      ████░          ███░░        ████░     ██░░░
Execution           █████          ███░░        ████░     ██░░░
Persistence         ████░          ███░░         █████    ██░░░
Privilege Esc.      ████░          ███░░         █████    ███░░
Defense Evasion     ███░░          ██░░░         ████░    ██░░░
Credential Access   █████          ███░░         █████    ████░
Lateral Movement    ████░          ███░░         ████░    ███░░
Exfiltration        ███░░          ███░░         ████░    ███░░
Impact              █████          ████░         █████    ████░
─────────────────────────────────────────────────────────────────────
OVERALL             82%            61%           88%       45%
```

---

## Remediation Roadmap by Framework

### For NIST-Anchored Organizations (FedRAMP, FISMA)
1. Enhance SC-7 to include DNS monitoring requirement
2. Formally adopt SR-3/SR-4 with SBOM tooling
3. Document GenAI data handling in DM policy section
4. Add Kerberos AES-only requirement to IA-5 implementation guidance

### For ISO 27001-Certified Organizations
1. Supplement A.8.15 with centralized SIEM forwarding requirement (NIST AU-9 analog)
2. Add technical SBOM scanning requirement to A.5.19/5.20
3. Map specific LOLBin restrictions to A.8.19 implementation
4. Implement AD-specific hardening guide as A.8.2/5.17 supplement

### For CIS-Framework Organizations
1. Add AD security benchmark to Control 5/6 coverage
2. Adopt DNS security controls under Control 9 (DNS-layer protection)
3. Add supply chain SCA requirement to Control 2

### For SOC 2-Only Organizations
High priority — consider adopting CIS IG2 as a technical supplement. Immediate additions:
1. **CIS 8.9** — Centralize audit logs (addresses T1070 gap)
2. **CIS 10.7** — Behavioral EDR (addresses T1055, T1059 gaps)
3. **CIS 5.4** — Restrict admin privileges (addresses T1134, T1548 gaps)
4. **CIS 4.1** — Secure configurations (addresses T1053, T1543 gaps)
5. **CIS 11.4** — Isolated recovery data (addresses T1490 gap)
