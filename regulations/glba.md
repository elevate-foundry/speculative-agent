# Gramm-Leach-Bliley Act (GLBA) Safeguards Rule
## 15 U.S.C. § 6801; 16 CFR Part 314 (FTC Safeguards Rule, amended 2023)

### 15 U.S.C. 6801 — Protection of nonpublic personal information

It is the policy of the Congress that each financial institution has an
affirmative and continuing obligation to respect the privacy of its customers
and to protect the security and confidentiality of those customers' nonpublic
personal information (NPI).

### 16 CFR 314.4 — Elements of an information security program

A financial institution must implement a comprehensive information security program
that includes: (a) qualified individual responsible; (b) risk assessment;
(c) safeguards including: access controls, encryption of customer information,
secure development, multi-factor authentication, audit logging, monitoring;
(d) testing and monitoring; (e) vendor oversight; (f) incident response plan;
(g) annual reporting to board.

### 16 CFR 314.4(f) — Secure disposal

A financial institution must implement policies for secure disposal of customer
information in any format no longer needed for business operations or required
by applicable law. Disposal must render the data unreadable.

### Compliance Lattice Mapping

| Action | GLBA Verdict | Condition |
|--------|-------------|-----------|
| Delete NPI after retention period (secure) | PERMIT | 314.4(f) — required disposal |
| Delete NPI during required retention | BLOCK | Legal retention obligation |
| Write NPI without access controls | BLOCK | 314.4(c)(1) access controls |
| Transmit NPI without encryption | BLOCK | 314.4(c)(3) encryption in transit |
| Read NPI | CONDITIONAL | Must have business purpose |
