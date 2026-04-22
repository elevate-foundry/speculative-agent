# China PIPL — Personal Information Protection Law

**Citation:** 中华人民共和国个人信息保护法, effective November 1, 2021  
**Regulator:** Cyberspace Administration of China (CAC); also MIIT, MPS  
**Applicability:** Processing of personal information of individuals located
in China, regardless of processor location. Extra-territorial effect similar to GDPR.

---

## Key Operative Provisions

### Art. 6 — Minimum Necessity

> Personal information processing shall have a clear and reasonable purpose,
> shall be directly relevant to the processing purpose, and shall be limited
> to the minimum scope necessary to achieve the processing purpose.
> Collection of personal information shall not be excessive relative to
> the processing purpose.

### Art. 13 — Legal Bases for Processing

> Personal information processors may process personal information only if
> one of the following conditions is met:
> (1) Obtaining the individual's consent;
> (2) Necessary for concluding or performing a contract;
> (3) Necessary for fulfilling legal duties;
> (4) Necessary for responding to public health emergencies;
> (5) Conducting news reporting or public interest supervision;
> (6) Personal information already disclosed by the individual;
> (7) Other circumstances provided by laws and regulations.

### Art. 17 — Notification Requirements

> Before processing personal information, the personal information processor
> shall truthfully, accurately, and completely inform the individual of:
> (1) The identity and contact of the personal information processor;
> (2) The purpose and method of processing;
> (3) The types of personal information to be processed;
> (4) The retention period;
> (5) How individuals can exercise their rights.

### Art. 38 — Cross-Border Transfer Restrictions

> Where a personal information processor needs to provide personal information
> to overseas parties, one of the following conditions shall be met:
> (1) Pass a security assessment organized by the CAC (required for critical
>     information infrastructure operators and large-scale processors);
> (2) Obtain personal information protection certification from a specialized
>     institution recognized by the CAC;
> (3) Execute a standard contract with the overseas recipient per CAC template;
> (4) Other conditions specified by laws, regulations, or the CAC.

### Art. 51 — Security Obligations

> Personal information processors shall adopt the following measures to ensure
> personal information processing complies with laws and regulations, and
> prevent unauthorized access, disclosure, tampering, or loss:
> (1) Formulate internal management systems and operating procedures;
> (2) Implement classified management of personal information;
> (3) Adopt security technical measures such as encryption and de-identification;
> (4) Reasonably determine operational authority over personal information;
> (5) Conduct regular training for personnel;
> (6) Formulate and organize emergency plans for personal information security incidents.

### Art. 55 — Personal Information Protection Impact Assessments

> Before carrying out the following activities, a personal information protection
> impact assessment shall be conducted:
> (1) Processing sensitive personal information;
> (2) Using personal information for automated decision-making;
> (3) Providing personal information to overseas parties.

---

## Compliance Lattice Mapping

| Article | Constraint | Weight λ |
|---------|-----------|----------|
| Art. 6 — Minimum Necessity | `Block` for excessive data collection | 2 |
| Art. 13 — Legal Basis | `Block` if no legal basis | 2 |
| Art. 38 — Cross-Border | `Block` for CAC-unapproved overseas transfer | 2 |
| Art. 51 — Security | Encryption + audit log required | 2 |
| Art. 55 — Impact Assessment | `Conditional` for automated decisions | 1 |

---

## Critical Notes for Autonomous Agents

PIPL Art. 38 is the most operationally significant constraint for cloud-based
agentic systems: **sending Chinese personal data to OpenAI, Anthropic, or Google
(US-based providers) may require CAC security assessment approval**, which can
take months. This creates a hard compliance gate:

```
if data_jurisdiction == "CN" and provider in ("openai", "anthropic", "google"):
    verdict = Block  # unless CAC assessment on file
```

PIPL Art. 55 requires a Personal Information Protection Impact Assessment before
any automated decision-making affecting individuals — directly applicable to
agentic AI systems making consequential decisions.
