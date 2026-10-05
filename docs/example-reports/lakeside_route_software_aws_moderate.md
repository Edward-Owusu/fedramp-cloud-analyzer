# FedRAMP readiness pre-check: Lakeside Route Software (fictional)

Provider: aws | NIST SP 800-53 moderate baseline | 17 resources | Generated 2026-10-05 21:32 UTC

- Readiness: **27/100 (Not ready)**
- Findings: **31**, of which critical: **7**

## Service areas

| Area | Status | Checks failing | Resources affected |
|---|---|---|---|
| Identity | Critical gaps | 5 of 5 | 5 |
| Logging and monitoring | Critical gaps | 4 of 4 | 1 |
| Network | Critical gaps | 3 of 3 | 3 |
| Storage | Critical gaps | 4 of 4 | 3 |
| Databases | Critical gaps | 3 of 3 | 1 |
| Compute | Gaps | 2 of 2 | 2 |
| Encryption keys | Gaps | 1 of 1 | 1 |

## Findings

### Identity

- **[CRITICAL] IAM-01** Root or global administrator account without MFA: `lakeside-prod`. The root or global administrator account has no MFA. _Controls: IA-2(1). Fix: Protect the root account with a hardware security key and store recovery details securely._
- **[HIGH] IAM-02** Root account has access keys: `lakeside-prod`. The root account has active access keys. _Controls: AC-6. Fix: Delete root access keys; use individual roles with least privilege for automation._
- **[HIGH] IAM-03** Console user without MFA: `dev.kim`. Can sign in to the console without MFA. _Controls: IA-2(1), IA-2(2). Fix: Require MFA for every console user, ideally through single sign-on with phishing-resistant MFA._
- **[HIGH] IAM-03** Console user without MFA: `ops.brennan`. Can sign in to the console without MFA. _Controls: IA-2(1), IA-2(2). Fix: Require MFA for every console user, ideally through single sign-on with phishing-resistant MFA._
- **[MEDIUM] IAM-04** Access keys older than the rotation period: `ci-deploy-bot`. Access key is 700 days old (limit 90). _Controls: IA-5. Fix: Rotate the keys, or replace long-lived keys with short-lived role credentials._
- **[MEDIUM] IAM-04** Access keys older than the rotation period: `dev.kim`. Access key is 420 days old (limit 90). _Controls: IA-5. Fix: Rotate the keys, or replace long-lived keys with short-lived role credentials._
- **[MEDIUM] IAM-05** Administrator permissions attached directly to a user: `ci-deploy-bot`. Administrator policy attached directly to the user. _Controls: AC-6, AC-2. Fix: Remove direct administrator policies and grant elevated access through roles or groups that are reviewed._
- **[MEDIUM] IAM-05** Administrator permissions attached directly to a user: `dev.alvarez`. Administrator policy attached directly to the user. _Controls: AC-6, AC-2. Fix: Remove direct administrator policies and grant elevated access through roles or groups that are reviewed._
- **[MEDIUM] IAM-05** Administrator permissions attached directly to a user: `dev.kim`. Administrator policy attached directly to the user. _Controls: AC-6, AC-2. Fix: Remove direct administrator policies and grant elevated access through roles or groups that are reviewed._

### Logging and monitoring

- **[CRITICAL] LOG-01** Audit logging is not on in every region: `lakeside-prod`. The audit trail does not cover every region. _Controls: AU-2, AU-12. Fix: Enable a multi-region audit trail (for example AWS CloudTrail or the Azure activity log) covering all accounts._
- **[HIGH] LOG-04** Cloud threat detection service is off: `lakeside-prod`. Threat detection is not enabled. _Controls: SI-4. Fix: Enable the provider's threat detection service (for example Amazon GuardDuty or Microsoft Defender for Cloud) and route alerts to your team._
- **[MEDIUM] LOG-02** Audit log integrity validation is off: `lakeside-prod`. Log file integrity validation is off. _Controls: AU-9. Fix: Turn on log file integrity validation and store logs in a write-protected location._
- **[MEDIUM] LOG-03** Audit logs are kept for less than the required period: `lakeside-prod`. Logs kept 90 days (minimum 365). _Controls: AU-11. Fix: Extend log retention to at least the required period; federal guidance in OMB M-21-31 calls for longer retention for many log types._

### Network

- **[CRITICAL] NET-01** Remote administration ports open to the internet: `legacy-admin`. Internet can reach port(s) 22, 3389. _Controls: SC-7, AC-17. Fix: Remove 0.0.0.0/0 rules for SSH, RDP, VNC, and Telnet; use a bastion host, VPN, or session manager service instead._
- **[CRITICAL] NET-01** Remote administration ports open to the internet: `test-anything`. Internet can reach port(s) 22, 23, 3389, 5900. _Controls: SC-7, AC-17. Fix: Remove 0.0.0.0/0 rules for SSH, RDP, VNC, and Telnet; use a bastion host, VPN, or session manager service instead._
- **[HIGH] NET-02** All ports open to the internet: `test-anything`. A rule allows every port from anywhere. _Controls: SC-7. Fix: Replace the all-ports rule with rules for only the ports and sources the workload needs._
- **[HIGH] NET-03** Load balancer allows plaintext HTTP or TLS below 1.2: `public-alb`. Listener accepts plaintext HTTP without redirecting and allows TLS 1.0. _Controls: SC-8, SC-13. Fix: Redirect HTTP to HTTPS and apply a TLS policy that allows only TLS 1.2 or 1.3 with FIPS-validated ciphers._

### Storage

- **[CRITICAL] STG-01** Storage bucket is publicly accessible: `app-static-assets`. Bucket allows public access. _Controls: AC-3, SC-7. Fix: Block public access at the bucket and account level, and share data through signed URLs or authenticated access instead._
- **[CRITICAL] STG-01** Storage bucket is publicly accessible: `customer-uploads`. Bucket allows public access. _Controls: AC-3, SC-7. Fix: Block public access at the bucket and account level, and share data through signed URLs or authenticated access instead._
- **[HIGH] STG-02** Storage bucket is not encrypted at rest: `customer-uploads`. Default encryption is off. _Controls: SC-28. Fix: Enable default encryption on the bucket, preferably with a customer-managed key._
- **[MEDIUM] STG-03** Storage bucket access logging is off: `app-static-assets`. Server access logging is off. _Controls: AU-2. Fix: Turn on server access logging and send the logs to a separate, restricted bucket._
- **[MEDIUM] STG-03** Storage bucket access logging is off: `customer-uploads`. Server access logging is off. _Controls: AU-2. Fix: Turn on server access logging and send the logs to a separate, restricted bucket._
- **[MEDIUM] STG-04** Versioning is off on a bucket holding sensitive data: `customer-uploads`. Holds sensitive data but versioning is off. _Controls: CP-9. Fix: Enable versioning so deleted or overwritten objects, including those hit by ransomware, can be recovered._
- **[MEDIUM] STG-04** Versioning is off on a bucket holding sensitive data: `nightly-db-exports`. Holds sensitive data but versioning is off. _Controls: CP-9. Fix: Enable versioning so deleted or overwritten objects, including those hit by ransomware, can be recovered._

### Databases

- **[CRITICAL] DB-01** Database is publicly accessible: `reporting-db`. Database accepts connections from the internet. _Controls: SC-7, AC-3. Fix: Disable public accessibility and place the database in private subnets reachable only from application servers._
- **[HIGH] DB-02** Database is not encrypted at rest: `reporting-db`. Storage encryption is off. _Controls: SC-28. Fix: Enable storage encryption; for existing databases, restore an encrypted copy from a snapshot._
- **[MEDIUM] DB-03** Database backups are off or kept too briefly: `reporting-db`. Automated backups are off. _Controls: CP-9. Fix: Enable automated backups with a retention period that meets your recovery requirements._

### Compute

- **[HIGH] CMP-01** Server disk is not encrypted: `route-optimizer`. Attached disk is not encrypted. _Controls: SC-28. Fix: Encrypt the volume (snapshot, copy encrypted, and replace) and turn on encryption by default for new volumes._
- **[MEDIUM] CMP-02** Server is not covered by patching and vulnerability scanning: `route-optimizer`. No patching or scanning agent reporting. _Controls: SI-2, RA-5. Fix: Install the patch management and scanning agent so the server is patched and scanned on schedule._
- **[MEDIUM] CMP-02** Server is not covered by patching and vulnerability scanning: `web-2`. No patching or scanning agent reporting. _Controls: SI-2, RA-5. Fix: Install the patch management and scanning agent so the server is patched and scanned on schedule._

### Encryption keys

- **[MEDIUM] KEY-01** Customer-managed key rotation is off: `app-data-key`. Automatic key rotation is off. _Controls: SC-12. Fix: Turn on automatic yearly rotation for customer-managed keys._


_This is an automated readiness pre-check of the configuration data supplied. It is not a FedRAMP assessment or authorization, does not replace a Third Party Assessment Organization (3PAO), and covers only the configuration checks listed. Baseline membership follows NIST SP 800-53B; verify against the official FedRAMP baseline._
