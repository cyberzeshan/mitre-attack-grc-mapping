# Purple Team ↔ GRC Alignment Guide

**Purpose:** Explains how to connect purple team exercise findings to GRC control gaps, remediation tracking, and audit evidence. Bridges the gap between offensive security testing results and compliance program management.

---

## Overview: Why Purple Team and GRC Must Connect

Purple team exercises test whether controls *actually work* — but findings often live in security team reports and never reach the GRC program. This results in:

- GRC assessments claiming a control is "implemented" when purple team proved it doesn't detect the tested technique
- Risk register entries that are stale because purple team found exploitable gaps that weren't escalated
- Audit evidence that doesn't include control validation test results

**The fix:** Map every purple team test scenario to a specific GRC control, and feed results back into the risk register and remediation tracking.

---

## Purple Team Planning: ATT&CK-to-Control Alignment

### Pre-Exercise: Define Control Scope

Before running emulation, identify which GRC controls are being tested:

```
PURPLE TEAM PLANNING MATRIX

Test Scenario          ATT&CK Technique    GRC Control Tested     Expected Detection
─────────────────────────────────────────────────────────────────────────────────────
Phishing simulation    T1566.001           SI-8, AT-2, CIS 9.4    Email sandbox block
Credential dump        T1003.001           IA-5, SC-28, CIS 5.4   EDR PPL alert
PowerShell C2          T1059.001           CM-7, AU-12, CIS 2.7   AMSI block + 4104 log
Lateral RDP            T1021.001           AC-17, SC-7, CIS 4.5   Firewall block
Scheduled persistence  T1053.005           CM-7, AU-12, CIS 4.1   SIEM event 4698 alert
Shadow copy deletion   T1490              CP-9, AU-12, CIS 11.3   EDR behavioral alert
Data staging + exfil   T1041              SC-7, SC-44, CIS 12.6   DLP/NDR alert
```

---

## Mapping Purple Team Findings to GRC Gaps

### Result Classification

| Finding | GRC Implication |
|:---|:---|
| **DETECTED + BLOCKED** | Control validated. Document as audit evidence. |
| **DETECTED, NOT BLOCKED** | Detection control works; preventive control gap. Update risk register. |
| **LOGGED, NOT ALERTED** | Log source present; SIEM tuning needed. Partial control deficiency. |
| **NOT LOGGED** | Control is not implemented or misconfigured. Critical finding — remediate. |
| **NOT DETECTED** | Control failure. Risk register update required; corrective action plan needed. |

### NIST RMF Integration

```
Purple Team Finding → RMF Step 6 (Monitor) → Control Deficiency
         ↓
   Control Assessment Finding (CA-8, CA-9 equivalent)
         ↓
   Plan of Action & Milestones (POA&M) entry
         ↓
   Remediation → Re-test → Update control status
```

### ISO 27001 Integration

Purple team findings map to:
- **A.5.36** — Compliance with policies and standards (control effectiveness)
- **A.8.8** — Vulnerability management (technique exploitability)
- **A.5.24** — Information security incident management (detection capability)
- **Nonconformity** → **Corrective action** in your ISO 27001 corrective action register

### SOC 2 Integration

Purple team findings as SOC 2 exception evidence:
- CC4.1 — Monitoring evaluation (test confirms/denies control effectiveness)
- CC4.2 — Deficiency evaluation and communication (findings = reportable deficiencies if material)

---

## Sample Purple Team → GRC Report Template

```markdown
## Purple Team Finding #PT-2024-007

**Test Scenario:** LSASS Memory Dump via ProcDump
**ATT&CK Technique:** T1003.001 — LSASS Memory
**Date Tested:** 2024-11-15
**Tester:** [Red Team Lead]
**GRC Controls Tested:**
  - NIST IA-5 (Authenticator Management)
  - NIST SC-28 (Protection of Information at Rest)
  - CIS 5.4 (Restrict Administrator Privileges)
  - CIS 13.2 (Host-Based IDS/EDR)

**Result:** NOT DETECTED — No EDR alert generated

**Root Cause:** EDR deployed but LSASS PPL (Protected Process Light) not enabled.
Credential Guard not deployed on this system class.

**GRC Impact:**
  - NIST SC-28 marked PARTIALLY IMPLEMENTED (encryption at rest exists; in-memory protection absent)
  - NIST IA-5 enhancement for credential protection NOT MET
  - Risk Register update: T1003.001 residual risk elevated from MEDIUM → HIGH

**Remediation:**
  - Enable PPL for LSASS: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1
  - Enable Credential Guard via Group Policy
  - Verify EDR tamper protection enabled

**Remediation Owner:** [Endpoint Security Team]
**Target Completion:** 30 days (NIST CP-2 based prioritization)
**Retest Required:** Yes — retest after remediation to confirm resolution

**Audit Evidence:**
  - Pre-remediation: Screenshot of undetected ProcDump execution [attached]
  - Post-remediation: [pending retest]
```

---

## Purple Team → Risk Register Integration

### Risk Entry Template (ATT&CK-Informed)

```
RISK ID: RISK-2024-089
TECHNIQUE: T1003.001 — LSASS Memory Dump
THREAT ACTOR: Ransomware affiliates, nation-state APT
LIKELIHOOD: HIGH (purple team confirmed exploitable)
IMPACT: CRITICAL (full credential compromise → domain takeover path)
INHERENT RISK: CRITICAL

CURRENT CONTROLS:
  - NIST IA-5: Partial (password policy present; in-memory protection absent)
  - NIST SC-28: Partial (at-rest encryption present; runtime memory unprotected)
  - CIS 5.4: Partial (admin restricted; debug privilege not locked down)

CONTROL EFFECTIVENESS: INSUFFICIENT
RESIDUAL RISK: HIGH

REMEDIATION:
  - Enable LSASS PPL (30 days)
  - Deploy Credential Guard (60 days)
  - EDR rule tuning for memory access patterns (15 days)

POST-REMEDIATION TARGET RISK: MEDIUM
```

---

## Annual Purple Team ↔ GRC Calendar

```
Q1: INITIAL ACCESS FOCUS
  - T1566 Phishing emulation → validate SI-8, AT-2, CIS 9
  - T1190 Exploit external app → validate RA-5, SI-2
  - GRC: Update vulnerability management control status

Q2: EXECUTION & PERSISTENCE FOCUS
  - T1059 PowerShell C2 → validate CM-7, AU-12, CIS 2.7
  - T1053 Scheduled tasks → validate CM-7, CIS 4.1
  - GRC: Update configuration management and logging control status

Q3: CREDENTIAL ACCESS & LATERAL MOVEMENT FOCUS
  - T1003 LSASS dump → validate IA-5, SC-28, CIS 5.4, CIS 13.2
  - T1021 RDP lateral → validate AC-17, SC-7
  - GRC: Update access control and boundary protection status

Q4: IMPACT SIMULATION FOCUS
  - T1486 Ransomware simulation → validate CP-9, SI-3, IR-4
  - T1490 Shadow copy deletion → validate CP-9, AU-12
  - GRC: Update continuity, backup, and incident response status
       Annual risk register review and remediation closure
```

---

## Key Metrics: Purple Team → GRC Program Health

| Metric | Target | Measure |
|:---|:---:|:---|
| Control validation coverage | >80% of P1 techniques tested annually | # P1 techniques tested / total P1 techniques |
| Mean time to GRC update after finding | <5 business days | Date finding → date risk register updated |
| Control deficiencies closed within SLA | >90% | Closed on time / total findings |
| Retest pass rate | >85% | Retests that confirm remediation / total retests |
| Risk register ATT&CK coverage | 100% of P1/P2 risks have technique mapping | # mapped entries / total high-risk entries |
