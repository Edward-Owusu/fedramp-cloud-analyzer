"""Load a cloud inventory and evaluate resource checks.

Each check returns ``None`` (not applicable to this resource), ``NOT_ASSESSED`` (data missing),
``(PASS, "")``, or ``(FAIL, "explanation")``. Missing data is never treated as a pass.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

PASS, FAIL, NOT_ASSESSED, NOT_APPLICABLE = "PASS", "FAIL", "NOT_ASSESSED", "NOT_APPLICABLE"
RESOURCE_TYPES = ("storage_bucket", "security_group", "compute_instance", "database",
                  "load_balancer", "iam_user", "kms_key")
_MISSING = object()


class DataError(ValueError):
    """Raised when the inventory cannot be read."""


def parse_inventory(text: str) -> dict:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DataError(f"The file is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise DataError("The inventory must be a JSON object with 'account' and 'resources'.")
    resources = data.get("resources", [])
    if not isinstance(resources, list):
        raise DataError("'resources' must be a list.")
    seen = set()
    for i, r in enumerate(resources, start=1):
        if not isinstance(r, dict) or "id" not in r or "type" not in r:
            raise DataError(f"Resource #{i} needs at least an 'id' and a 'type'.")
        if r["type"] not in RESOURCE_TYPES:
            raise DataError(f"Resource '{r['id']}' has unknown type '{r['type']}'. "
                            f"Allowed: {', '.join(RESOURCE_TYPES)}.")
        if r["id"] in seen:
            raise DataError(f"Resource id '{r['id']}' appears more than once.")
        seen.add(r["id"])
    data.setdefault("account", {})
    data["resources"] = resources
    return data


def load_inventory(path: str | Path) -> dict:
    return parse_inventory(Path(path).read_text(encoding="utf-8-sig"))


def _get(obj: dict, key: str) -> Any:
    return obj.get(key, _MISSING) if isinstance(obj, dict) else _MISSING


def _flag(obj: dict, key: str, bad_when: bool, detail: str):
    v = _get(obj, key)
    if v is _MISSING or v is None:
        return NOT_ASSESSED
    return (FAIL, detail) if bool(v) == bad_when else (PASS, "")


def _tls_lt(a: str, b: str) -> bool:
    try:
        return tuple(int(x) for x in str(a).split(".")) < tuple(int(x) for x in str(b).split("."))
    except ValueError:
        return True


# ----- resource checks ---------------------------------------------------------------------------

def stg01(r, p): return _flag(r, "public_access", True, "Bucket allows public access.")
def stg02(r, p): return _flag(r, "encrypted", False, "Default encryption is off.")
def stg03(r, p): return _flag(r, "access_logging", False, "Server access logging is off.")


def stg04(r, p):
    if _get(r, "sensitive_data") is not True:
        return None
    return _flag(r, "versioning", False, "Holds sensitive data but versioning is off.")


def _open_rules(r) -> list[dict] | object:
    rules = _get(r, "ingress")
    if rules is _MISSING:
        return _MISSING
    return [x for x in rules if isinstance(x, dict) and x.get("cidr") in ("0.0.0.0/0", "::/0")]


def net01(r, p):
    rules = _open_rules(r)
    if rules is _MISSING:
        return NOT_ASSESSED
    exposed = sorted({port for x in rules for port in p["admin_ports"]
                      if int(x.get("from_port", 0)) <= port <= int(x.get("to_port", 65535))})
    if exposed:
        return FAIL, f"Internet can reach port(s) {', '.join(map(str, exposed))}."
    return PASS, ""


def net02(r, p):
    rules = _open_rules(r)
    if rules is _MISSING:
        return NOT_ASSESSED
    if any(int(x.get("from_port", 0)) <= 0 and int(x.get("to_port", 65535)) >= 65535 for x in rules):
        return FAIL, "A rule allows every port from anywhere."
    return PASS, ""


def net03(r, p):
    http, tls = _get(r, "allows_http"), _get(r, "min_tls")
    if http is _MISSING and tls is _MISSING:
        return NOT_ASSESSED
    problems = []
    if http is True:
        problems.append("accepts plaintext HTTP without redirecting")
    if tls is not _MISSING and _tls_lt(tls, p["min_tls"]):
        problems.append(f"allows TLS {tls}")
    return (FAIL, "Listener " + " and ".join(problems) + ".") if problems else (PASS, "")


def cmp01(r, p): return _flag(r, "disk_encrypted", False, "Attached disk is not encrypted.")
def cmp02(r, p): return _flag(r, "patch_agent", False, "No patching or scanning agent reporting.")
def db01(r, p): return _flag(r, "publicly_accessible", True, "Database accepts connections from the internet.")
def db02(r, p): return _flag(r, "encrypted", False, "Storage encryption is off.")


def db03(r, p):
    days = _get(r, "backup_retention_days")
    if days is _MISSING or days is None:
        return NOT_ASSESSED
    need = p["db_backup_min_retention_days"]
    if int(days) < need:
        return FAIL, ("Automated backups are off." if int(days) == 0
                      else f"Backups kept {days} days (minimum {need}).")
    return PASS, ""


def iam03(r, p):
    if _get(r, "console_access") is not True:
        return None
    return _flag(r, "mfa_enabled", False, "Can sign in to the console without MFA.")


def iam04(r, p):
    age = _get(r, "access_key_age_days")
    if age is _MISSING:
        return NOT_ASSESSED
    if age is None:
        return None  # user has no access keys
    limit = p["access_key_max_age_days"]
    return (FAIL, f"Access key is {age} days old (limit {limit}).") if int(age) > limit else (PASS, "")


def iam05(r, p): return _flag(r, "admin_policy_direct", True, "Administrator policy attached directly to the user.")


def key01(r, p):
    if _get(r, "customer_managed") is False:
        return None
    return _flag(r, "rotation_enabled", False, "Automatic key rotation is off.")


# ----- account checks ----------------------------------------------------------------------------

def iam01(a, p): return _flag(a, "root_mfa", False, "The root or global administrator account has no MFA.")
def iam02(a, p): return _flag(a, "root_access_keys", True, "The root account has active access keys.")


def log01(a, p):
    log = _get(a, "audit_logging")
    if log is _MISSING:
        return NOT_ASSESSED
    if not log.get("enabled"):
        return FAIL, "No audit trail is enabled."
    if log.get("all_regions") is False:
        return FAIL, "The audit trail does not cover every region."
    return PASS, ""


def log02(a, p):
    log = _get(a, "audit_logging")
    if log is _MISSING or not log.get("enabled"):
        return None if log is not _MISSING else NOT_ASSESSED
    return _flag(log, "integrity_validation", False, "Log file integrity validation is off.")


def log03(a, p):
    log = _get(a, "audit_logging")
    if log is _MISSING or "retention_days" not in log:
        return NOT_ASSESSED
    need = p["log_retention_min_days"]
    days = int(log["retention_days"])
    return (FAIL, f"Logs kept {days} days (minimum {need}).") if days < need else (PASS, "")


def log04(a, p): return _flag(a, "threat_detection", False, "Threat detection is not enabled.")


CHECKS: dict[str, tuple[str, Callable]] = {
    "STG-01": ("storage_bucket", stg01), "STG-02": ("storage_bucket", stg02),
    "STG-03": ("storage_bucket", stg03), "STG-04": ("storage_bucket", stg04),
    "NET-01": ("security_group", net01), "NET-02": ("security_group", net02),
    "NET-03": ("load_balancer", net03),
    "CMP-01": ("compute_instance", cmp01), "CMP-02": ("compute_instance", cmp02),
    "DB-01": ("database", db01), "DB-02": ("database", db02), "DB-03": ("database", db03),
    "IAM-01": ("account", iam01), "IAM-02": ("account", iam02),
    "IAM-03": ("iam_user", iam03), "IAM-04": ("iam_user", iam04), "IAM-05": ("iam_user", iam05),
    "LOG-01": ("account", log01), "LOG-02": ("account", log02), "LOG-03": ("account", log03),
    "LOG-04": ("account", log04),
    "KEY-01": ("kms_key", key01),
}
