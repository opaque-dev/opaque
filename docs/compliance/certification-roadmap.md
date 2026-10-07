# Certification status and assessment material

The public core provides implementation and test evidence for a self-hosted
agent-security deployment. This repository does not provide a SOC 2 report,
ISO 27001 certificate, FedRAMP authorization or a validated FIPS product build.

## Available inspection material

| Material | What to inspect |
| --- | --- |
| [Control mapping](control-mapping.md) | Selected SOC 2 and NIST control references, mechanisms and deployment limits |
| [Hardening guide](hardening.md) | Custody, identity, review, policy and export configuration |
| [Release verification](verifying-releases.md) | Checksums, release signatures, SBOMs and the availability of provenance/dependency evidence |
| [FIPS assessment](fips-assessment.md) | Primitive inventory, recorded build experiments and remaining migration gaps |
| [Evidence checkpoints](../evidence-checkpoints.md) | Enrolled producer verification, declared ranges, retention and continuity limits |
| [Disclosure policy](https://github.com/opaque-dev/opaque/blob/main/SECURITY.md) | Reporting channel and response/support policy |

Verify this material against the exact archive and source revision you deploy.
A workflow step or source test does not establish that a specific published
artifact passed it. Cryptographic-module experiments do not make current product
binaries validated.

## Deployment assessment

The deploying organization owns host protection, IdP policy, provider credentials,
SIEM operations, backup/recovery and its authorization process. The broker supplies
controls and evidence within that environment; the
[control mapping](control-mapping.md#customer-responsibilities) states the split.

Certification scope, external assessments and future cryptographic variants need
separate qualification. No dates or certification commitments are attached to
this material.
