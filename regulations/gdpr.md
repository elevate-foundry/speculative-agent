# EU General Data Protection Regulation (GDPR)
## Regulation (EU) 2016/679

### Article 5 — Principles relating to processing

Personal data shall be: (a) processed lawfully, fairly and transparently;
(b) collected for specified, explicit and legitimate purposes (purpose limitation);
(c) adequate, relevant and limited to what is necessary (data minimisation);
(d) accurate and kept up to date; (e) kept no longer than necessary (storage limitation);
(f) processed with appropriate security (integrity and confidentiality).

### Article 17 — Right to erasure (right to be forgotten)

The data subject has the right to erasure without undue delay where:
(a) data no longer necessary for the purpose collected;
(b) consent withdrawn and no other legal ground exists;
(c) data subject objects under Art. 21(1);
(d) data unlawfully processed;
(e) erasure required by Union or Member State law;
(f) data collected in relation to information society services under Art. 8(1).

Exceptions: Art. 17(3) — erasure does not apply where processing is necessary for:
freedom of expression; legal obligation; public health; archiving/research; legal claims.

### Article 25 — Data protection by design and by default

Controllers shall implement appropriate technical and organisational measures
to ensure that, by default, only personal data which are necessary for each
specific purpose are processed.

### Article 32 — Security of processing

Taking into account the state of the art and costs, controllers shall implement
measures including: (a) pseudonymisation and encryption; (b) confidentiality,
integrity, availability; (c) ability to restore availability after incidents;
(d) regular testing and evaluation.

### Compliance Lattice Mapping

| Action | GDPR Verdict | Condition |
|--------|-------------|-----------|
| Delete personal data (requested) | PERMIT | Art. 17(1) applies |
| Delete personal data (no request) | CONDITIONAL | Must verify Art. 17(3) exceptions |
| Delete personal data (legal hold) | BLOCK | Art. 17(3)(e) — legal obligation |
| Retain beyond purpose | BLOCK | Art. 5(1)(e) storage limitation |
| Write personal data without basis | BLOCK | Art. 5(1)(a) lawfulness |
| Read personal data | CONDITIONAL | Must have lawful basis Art. 6 |
