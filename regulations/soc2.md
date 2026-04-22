# SOC 2 — AICPA Trust Services Criteria
## Common Criteria (CC) relevant to autonomous agent actions

### CC6.1 — Logical and Physical Access Controls

The entity implements logical access security software, infrastructure, and
architectures over protected information assets to protect them from security
events to meet the entity's objectives.

**Audit log requirement:** All access to and modifications of sensitive data
must be logged with sufficient detail to reconstruct the sequence of events.
Logs must be tamper-evident (hash-chained or write-once storage).

### CC6.2 — Prior to issuing system credentials

New internal and external users are registered and authorized prior to
accessing the system to meet the entity's objectives.

### CC6.3 — Role-based access

The entity authorizes, modifies, or removes access to data, software, functions,
and other protected information assets based on approved and documented access
requests, within the framework of the entity's established information security
policies and in accordance with business needs.

### CC7.2 — Monitoring of system components

The entity monitors system components and the operation of those components
for anomalies that are indicative of malicious acts, natural disasters, and
errors affecting the entity's ability to meet its objectives.

### CC9.2 — Risk management

The entity assesses and manages risks associated with vendors and business partners.

### Compliance Lattice Mapping

| Action | SOC2 Verdict | Condition |
|--------|-------------|-----------|
| Any action without audit log entry | BLOCK | CC6.1 — tamper-evident log required |
| Delete audit log entries | BLOCK | CC6.1 — logs are immutable |
| Access data without authorization record | BLOCK | CC6.3 |
| Execute action with no identity attribution | BLOCK | CC6.2 |
| All permitted actions | CONDITIONAL | Must appear in audit log |
