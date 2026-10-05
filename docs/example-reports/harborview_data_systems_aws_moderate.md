# FedRAMP readiness pre-check: Harborview Data Systems (fictional)

Provider: aws | NIST SP 800-53 moderate baseline | 12 resources | Generated 2026-10-05 21:32 UTC

- Readiness: **97/100 (Strong)**
- Findings: **2**, of which critical: **0**

## Service areas

| Area | Status | Checks failing | Resources affected |
|---|---|---|---|
| Identity | Gaps | 1 of 5 | 1 |
| Logging and monitoring | Pass | 0 of 4 | 0 |
| Network | Pass | 0 of 3 | 0 |
| Storage | Gaps | 1 of 4 | 1 |
| Databases | Pass | 0 of 3 | 0 |
| Compute | Pass | 0 of 2 | 0 |
| Encryption keys | Pass | 0 of 1 | 0 |

## Findings

### Identity

- **[MEDIUM] IAM-04** Access keys older than the rotation period: `ci-deploy`. Access key is 120 days old (limit 90). _Controls: IA-5. Fix: Rotate the keys, or replace long-lived keys with short-lived role credentials._

### Storage

- **[MEDIUM] STG-03** Storage bucket access logging is off: `access-logs`. Server access logging is off. _Controls: AU-2. Fix: Turn on server access logging and send the logs to a separate, restricted bucket._


_This is an automated readiness pre-check of the configuration data supplied. It is not a FedRAMP assessment or authorization, does not replace a Third Party Assessment Organization (3PAO), and covers only the configuration checks listed. Baseline membership follows NIST SP 800-53B; verify against the official FedRAMP baseline._
