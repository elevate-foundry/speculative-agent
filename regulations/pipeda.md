# Canada PIPEDA — Personal Information Protection and Electronic Documents Act

**Citation:** S.C. 2000, c. 5; substantially amended by Bill C-11 (pending) and
the Digital Charter Implementation Act  
**Regulator:** Office of the Privacy Commissioner of Canada (OPC)  
**Applicability:** Private-sector organizations collecting, using, or disclosing
personal information in the course of commercial activities in Canada.

---

## Schedule 1 — Principles of Fair Information Practices

### Principle 1 — Accountability

> An organization is responsible for personal information under its control
> and shall designate an individual or individuals accountable for the
> organization's compliance with the following principles.

### Principle 2 — Identifying Purposes

> The purposes for which personal information is collected shall be identified
> by the organization at or before the time the information is collected.

### Principle 4.3 — Consent

> The knowledge and consent of the individual are required for the collection,
> use, or disclosure of personal information, except where inappropriate.
> Consent can be expressed or implied depending on sensitivity of information.

### Principle 4.5 — Limiting Use, Disclosure, and Retention

> Personal information shall not be used or disclosed for purposes other than
> those for which it was collected, except with the consent of the individual
> or as required by law. Personal information shall be retained only as long
> as necessary for the fulfilment of those purposes.

### Principle 4.7 — Safeguards

> Personal information shall be protected by security safeguards appropriate
> to the sensitivity of the information. The safeguards shall protect personal
> information against loss or theft, as well as unauthorized access, disclosure,
> copying, use, or modification. Organizations shall make their employees aware
> of the importance of maintaining the confidentiality of personal information.

### Principle 4.9 — Individual Access

> Upon request, an individual shall be informed of the existence, use, and
> disclosure of his or her personal information and shall be given access to
> that information. An individual shall be able to challenge the accuracy and
> completeness of the information and have it amended as appropriate.

---

## Bill C-27 — Consumer Privacy Protection Act (Pending)

> **s. 55 — Automated Decision Systems.** An organization that uses an automated
> decision system to make a prediction, recommendation, or decision about an
> individual that could significantly impact the individual shall, on request,
> provide the individual with an explanation of the prediction, recommendation,
> or decision, and of how the personal information used to make it was obtained.

---

## Compliance Lattice Mapping

| Provision | Constraint | Weight λ |
|-----------|-----------|----------|
| Principle 1 — Accountability | Designated compliance officer required | 1 |
| Principle 4.3 — Consent | `Block` for unconsented PII processing | 2 |
| Principle 4.5 — Limiting Use | `Block` for purpose-exceeding use | 2 |
| Principle 4.7 — Safeguards | Audit log + encryption required | 2 |
| Bill C-27 s.55 — ADS | Explainability required for impactful decisions | 1 |

---

## Notes

- PIPEDA applies federally; Quebec (Law 25), Alberta (PIPA), and BC (PIPA) have
  substantially similar provincial laws that apply instead within those provinces.
- Quebec Law 25 (effective 2023) is the closest Canadian analog to GDPR,
  requiring privacy impact assessments and mandatory breach notification.
