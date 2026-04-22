# Metro 2 Format and CDIA Standards
## Consumer Data Industry Association (CDIA) Credit Reporting Resource Guide

### Metro 2 Format Overview

Metro 2 is the standard data format for furnishing consumer credit information
to Consumer Reporting Agencies (CRAs). It defines: Base Segment (required
account data), J1/J2 Segments (associated consumer data), K1-K4 Segments
(specialized account data), L1 Segment (legal order/insurance claim).

### Key Retention Standards

**Account History:** Furnishers must maintain complete and accurate account
history for the full reporting period. Premature deletion of account data
that is still within the reporting window violates FCRA accuracy requirements.

**Dispute Resolution:** When a consumer disputes an item, the furnisher must
conduct a reasonable investigation and update Metro 2 submissions accordingly.
Failure to delete inaccurate data after investigation is a FCRA violation.

**Date of First Delinquency (DOFD):** The DOFD is the critical date that
starts the 7-year FCRA reporting clock. This field must never be altered
or deleted — it is immutable once established.

### CDIA Data Accuracy Standards

Furnishers must report: accurate account status, correct balance, correct
payment history, accurate consumer identity information. Any system action
that modifies credit data must be logged and attributable to an authorized
furnisher with permissible purpose.

### Compliance Lattice Mapping

| Action | Metro2/CDIA Verdict | Condition |
|--------|-------------------|-----------|
| Delete DOFD field | BLOCK | FCRA 605 — immutable reporting anchor |
| Delete account within 7-year window | BLOCK | FCRA 605(a) — premature suppression |
| Delete inaccurate account after investigation | PERMIT | FCRA 611 — required correction |
| Modify payment history | CONDITIONAL | Must be result of verified dispute |
| Write account without permissible purpose | BLOCK | FCRA 607(a) |
