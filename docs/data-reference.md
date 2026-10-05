# Inventory reference

The tool reads one JSON file describing a cloud environment in a simple, provider-neutral form. Start from `samples/inventory_template.json`. Any field you cannot provide can be left out; checks that need it are reported as not assessed instead of passed.

## Top level

| Field | Description |
|---|---|
| `organization` | Name shown on the report |
| `provider` | `aws`, `azure`, `gcp`, or another label |
| `description` | Optional one-line description |
| `account` | Account-wide settings (below) |
| `resources` | List of resources, each with a unique `id`, a `type`, and an optional `name` |

## Account settings

| Field | Type | Check |
|---|---|---|
| `root_mfa` | true/false | IAM-01 |
| `root_access_keys` | true/false | IAM-02 |
| `audit_logging.enabled` | true/false | LOG-01 |
| `audit_logging.all_regions` | true/false | LOG-01 |
| `audit_logging.integrity_validation` | true/false | LOG-02 |
| `audit_logging.retention_days` | number | LOG-03 |
| `threat_detection` | true/false | LOG-04 |

## Resource types and fields

| `type` | Fields | Checks |
|---|---|---|
| `storage_bucket` | `public_access`, `encrypted`, `access_logging`, `versioning`, `sensitive_data` | STG-01 to STG-04 |
| `security_group` | `ingress`: list of `{cidr, from_port, to_port}` | NET-01, NET-02 |
| `load_balancer` | `allows_http` (plaintext HTTP without redirect), `min_tls` (e.g. `"1.2"`) | NET-03 |
| `compute_instance` | `disk_encrypted`, `patch_agent` | CMP-01, CMP-02 |
| `database` | `publicly_accessible`, `encrypted`, `backup_retention_days` (0 means off) | DB-01 to DB-03 |
| `iam_user` | `console_access`, `mfa_enabled`, `access_key_age_days` (null if no keys), `admin_policy_direct` | IAM-03 to IAM-05 |
| `kms_key` | `customer_managed`, `rotation_enabled` | KEY-01 |

## Building the inventory

Most of these values are available from each provider's console, command-line tools, or configuration inventory services, such as AWS Config and the AWS CLI, Azure Resource Graph, or Google Cloud Asset Inventory. Cloud security posture tools and open-source scanners also report many of them and can be mapped into this format.

For example, with the AWS CLI, `aws s3api get-public-access-block`, `aws s3api get-bucket-encryption`, `aws ec2 describe-security-groups`, `aws rds describe-db-instances`, `aws iam generate-credential-report`, and `aws cloudtrail describe-trails` return most of the fields above. Verify commands and field names against your provider's current documentation, and run them with read-only permissions.

The inventory describes your environment's weaknesses. Store it and the reports securely.

## Organization-defined parameters

Defaults are in `src/cloud_check/data/policy.json`: administration ports checked (22, 23, 3389, 5900), access key rotation period (90 days), minimum database backup retention (7 days), minimum audit log retention (365 days), and minimum TLS version (1.2). Override any of them with `--policy`.
