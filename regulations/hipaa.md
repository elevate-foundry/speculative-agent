# Health Insurance Portability and Accountability Act (HIPAA)
## 45 CFR Parts 160, 162, 164

### 45 CFR 164.502 — Uses and disclosures of protected health information

A covered entity may not use or disclose PHI except as permitted or required by this subpart.
Permitted uses include: treatment, payment, health care operations, patient authorization,
public interest activities, limited data set with data use agreement.

### 45 CFR 164.530(j) — Documentation and record retention

A covered entity must retain documentation required by this subpart for 6 years from
the date of its creation or the date when it last was in effect, whichever is later.

**CRITICAL for compliance lattice:** PHI records subject to HIPAA cannot be deleted
within the 6-year retention window without explicit regulatory exception.

### 45 CFR 164.312 — Technical safeguards (Security Rule)

Covered entities must implement: (a)(1) access controls; (a)(2)(i) unique user IDs;
(a)(2)(ii) emergency access procedure; (a)(2)(iii) automatic logoff;
(a)(2)(iv) encryption and decryption; (b) audit controls; (c) integrity controls;
(d) person or entity authentication; (e)(1) transmission security.

### Definition: Protected Health Information (PHI)

PHI means individually identifiable health information transmitted or maintained
in any form (electronic ePHI, paper, oral) by a covered entity or business associate.
Includes: names, dates (except year), geographic identifiers, phone/fax, email,
SSN, medical record numbers, health plan beneficiary numbers, account numbers,
certificate/license numbers, VINs, device identifiers, URLs, IPs, biometrics,
full-face photos, any other unique identifier.

### Compliance Lattice Mapping

| Action | HIPAA Verdict | Condition |
|--------|--------------|-----------|
| Delete PHI within 6-year window | BLOCK | 164.530(j) retention |
| Delete PHI after 6 years | CONDITIONAL | Must verify no active legal hold |
| Write PHI without authorization | BLOCK | 164.502 — no permitted purpose |
| Read PHI for treatment | PERMIT | 164.502(a)(1)(ii) |
| Read PHI for operations | CONDITIONAL | 164.502(a)(1)(iii) — minimum necessary |
| Transmit PHI without encryption | BLOCK | 164.312(e)(2)(ii) |
