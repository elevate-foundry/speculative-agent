# Google Generative AI Terms of Service & Prohibited Use Policy

**Source:** https://policies.google.com/terms/generative-ai (effective May 2024)  
**Applicability:** Gemini API, Gemini 2.5 Pro/Flash, all Google AI Studio models

---

## Key Operative Provisions

### Generative AI Prohibited Use Policy

> **Harmful or Illegal Content.** You may not generate content that facilitates
> illegal activity, incites violence, constitutes harassment, or violates
> third-party rights including privacy, IP, and defamation law.

> **Deceptive Practices.** You may not use Gemini to create content designed to
> deceive people about its AI origin or impersonate real individuals.

> **Dangerous Activities.** You may not use Gemini to provide instructions for
> dangerous activities including weapons synthesis, cyberattacks, or bypassing
> security controls.

### Google Cloud API Terms — Section 7: Responsible AI

> **7.1 Intended Use.** Customers must use Google AI services consistent with
> their intended purpose and must not attempt to extract model weights or
> circumvent safety classifiers.

> **7.2 Human Review.** For consequential automated decisions (credit, employment,
> medical, legal), customers must implement human review mechanisms before
> acting on model outputs.

### Data Processing & Privacy

> **Data Processing Terms.** Google processes API inputs under the Google Cloud
> Data Processing Addendum (GDPR-compliant). Inputs are not used to train
> Gemini models by default under API terms.

> **Retention.** Input/output data retained for 30 days for safety monitoring,
> then deleted. Enterprise customers can opt for 0-day retention.

### Compliance Certifications

> Google Cloud maintains: ISO 27001, SOC 2 Type II, SOC 3, FedRAMP High,
> HIPAA BAA availability, PCI DSS. Gemini API inherits these controls.

---

## Compliance Lattice Mapping

| Provision | Lattice Constraint | Weight |
|-----------|-------------------|--------|
| Prohibited Use — Harmful Content | `Block` for prohibited categories | λ=2 |
| §7.2 Human Review | `Conditional` for consequential decisions | λ=2 |
| Data Processing | `Conditional` for PII in prompts | λ=1 |
| ISO 27001 / SOC 2 | Audit logging required | λ=1 |

---

## Notes for Agentic Use

Google's §7.2 Human Review requirement aligns directly with the preflight
autonomy assessment: the model-voted autonomy level serves as a programmatic
proxy for risk-proportionate human oversight.
