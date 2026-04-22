# Brazil LGPD — Lei Geral de Proteção de Dados

**Citation:** Lei nº 13.709/2018, as amended by Lei nº 13.853/2019  
**Regulator:** Autoridade Nacional de Proteção de Dados (ANPD)  
**Applicability:** Any processing of personal data of individuals located in Brazil,
regardless of where the controller is established.

---

## Key Operative Provisions

### Art. 7 — Legal Bases for Processing

> Personal data processing may only be carried out when based on one of the
> following legal grounds:
> I. Consent of the data subject;
> II. Compliance with a legal obligation;
> III. Execution of public policies;
> IV. Carrying out studies by research bodies;
> V. Execution of a contract;
> VI. Exercise of rights in judicial, administrative, or arbitration proceedings;
> VII. Protection of the life or physical safety of a person;
> VIII. Protection of health;
> IX. Legitimate interests of the controller or third party;
> X. Credit protection.

### Art. 18 — Data Subject Rights

> The data subject has the right to obtain from the controller:
> I. Confirmation of the existence of processing;
> II. Access to the data;
> III. Correction of incomplete, inaccurate, or outdated data;
> IV. Anonymization, blocking, or deletion of unnecessary or excessive data;
> V. Portability of data to another service provider;
> VI. Deletion of personal data processed with the consent of the data subject;
> VII. Information about public and private entities with which the controller
>      has shared data;
> VIII. Information about the possibility of denying consent and the consequences.

### Art. 37 — Record-Keeping

> The controller and processor shall keep records of personal data processing
> operations, especially when based on legitimate interests.

### Art. 46 — Security Measures

> Processing agents shall adopt security, technical, and administrative measures
> capable of protecting personal data from unauthorized access and accidental or
> unlawful destruction, loss, alteration, communication, or any other form of
> improper or unlawful processing.

### Art. 49 — Systems Developed Outside Brazil

> Systems used for processing of personal data shall be structured to meet
> the security requirements and data protection standards established in
> regulations and in good practices.

---

## Compliance Lattice Mapping

| Article | Constraint | Weight λ |
|---------|-----------|----------|
| Art. 7 — Legal Basis | `Block` if no legal basis for processing | 2 |
| Art. 18 — Subject Rights | `Conditional` for actions affecting personal data | 1 |
| Art. 37 — Record-Keeping | Audit log required for all processing | 2 |
| Art. 46 — Security | Encryption and access controls required | 1 |
| Art. 49 — Foreign Systems | `Conditional` for cross-border data transfer | 1 |

---

## Relationship to GDPR

LGPD is structurally similar to GDPR but with key differences:
- **Legitimate interests** (Art. 7 IX) is broader — no balancing test required
- **Consent** must be free, informed, specific, and unambiguous (same as GDPR)
- **No DPO mandate** for most organizations (unlike GDPR Art. 37)
- **Penalties** up to 2% of Brazil revenue, capped at R$50M per violation
