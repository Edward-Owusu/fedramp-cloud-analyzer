# Methodology

## Purpose and scope

This tool is a readiness pre-check. It helps small cloud and software-as-a-service providers find common configuration gaps before engaging a Third Party Assessment Organization (3PAO) for a FedRAMP assessment. It checks configuration only. FedRAMP authorization also covers policies, procedures, documentation, personnel, and continuous monitoring, which this tool does not assess.

## Checks and controls

The 22 checks are grouped into seven service areas and mapped to NIST SP 800-53 Rev. 5 controls, the control catalog on which FedRAMP baselines are built.

| Area | Checks | Controls |
|---|---|---|
| Identity | Root MFA, root access keys, console MFA, key rotation, direct admin policies | IA-2(1), IA-2(2), IA-5, AC-6, AC-2 |
| Logging and monitoring | Multi-region audit trail, log integrity, retention, threat detection | AU-2, AU-12, AU-9, AU-11, SI-4 |
| Network | Admin ports and all ports open to the internet, plaintext HTTP or old TLS | SC-7, AC-17, SC-8, SC-13 |
| Storage | Public buckets, encryption, access logging, versioning | AC-3, SC-7, SC-28, AU-2, CP-9 |
| Databases | Public databases, encryption, backups | SC-7, AC-3, SC-28, CP-9 |
| Compute | Disk encryption, patching and scanning coverage | SC-28, SI-2, RA-5 |
| Encryption keys | Key rotation | SC-12 |

A check runs only when at least one of its controls is in the selected baseline. Baseline membership follows NIST SP 800-53B. FedRAMP baselines add FedRAMP-specific parameters and, in places, additional controls, so results should be confirmed against the official FedRAMP baseline.

## Outcomes and scoring

For each resource in scope, a check passes, fails, or is not assessed when the needed data is missing. Missing data never counts as a pass.

Each check carries a weight by severity (critical 10, high 6, medium 3, low 1). The readiness score is 100 minus the weighted share of failures, where each check contributes its weight multiplied by the share of its in-scope resources that fail:

```
readiness = 100 x (1 - sum(weight x failing / assessed) / sum(weight))
```

Bands: 90 or more Strong, 75 to below 90 Moderate gaps, 50 to below 75 Significant gaps, below 50 Not ready. A service area shows Critical gaps if any critical check fails in it, Gaps for any other failure, and Pass otherwise.

Severities reflect the author's judgment of how directly each gap could expose federal data or let an attacker in. They are a prioritization aid, not a quantitative risk model.

## Limitations

- Results depend on the accuracy and completeness of the inventory.
- The tool does not connect to cloud accounts; it reads an exported inventory.
- It is not a FedRAMP assessment and does not predict an authorization decision.
