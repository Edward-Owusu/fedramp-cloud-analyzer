import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cloud_check import assess, load_inventory, parse_inventory  # noqa: E402
from cloud_check.checks import NOT_APPLICABLE, NOT_ASSESSED, DataError  # noqa: E402
from cloud_check.cli import main  # noqa: E402
from cloud_check.engine import readiness_label  # noqa: E402
from cloud_check.reporting import WRITERS  # noqa: E402

WEAK = ROOT / "samples" / "lakeside_route_software_aws.json"
STRONG = ROOT / "samples" / "harborview_data_systems_aws.json"


def run(resources=None, account=None, baseline="moderate"):
    return assess({"organization": "T", "account": account or {}, "resources": resources or []}, baseline)


def failing(result):
    return {(f.check_id, f.resource) for f in result.findings}


def status(result, check_id):
    return next(s.status for s in result.checks if s.check_id == check_id)


class TestParsing(unittest.TestCase):
    def test_rejects_bad_inventories(self):
        with self.assertRaisesRegex(DataError, "valid JSON"):
            parse_inventory("{not json")
        with self.assertRaisesRegex(DataError, "unknown type"):
            parse_inventory(json.dumps({"resources": [{"id": "x", "type": "spaceship"}]}))
        with self.assertRaisesRegex(DataError, "more than once"):
            parse_inventory(json.dumps({"resources": [{"id": "x", "type": "kms_key"}, {"id": "x", "type": "kms_key"}]}))
        with self.assertRaisesRegex(DataError, "'id' and a 'type'"):
            parse_inventory(json.dumps({"resources": [{"name": "x"}]}))


class TestChecks(unittest.TestCase):
    def test_storage(self):
        r = run([{"id": "b", "type": "storage_bucket", "public_access": True, "encrypted": False,
                  "access_logging": False, "versioning": False, "sensitive_data": True}])
        self.assertTrue({("STG-01", "b"), ("STG-02", "b"), ("STG-03", "b"), ("STG-04", "b")} <= failing(r))

    def test_versioning_only_for_sensitive_buckets(self):
        r = run([{"id": "b", "type": "storage_bucket", "versioning": False, "sensitive_data": False}])
        self.assertEqual(status(r, "STG-04"), NOT_APPLICABLE)

    def test_security_groups(self):
        r = run([{"id": "ok", "type": "security_group", "ingress": [{"cidr": "0.0.0.0/0", "from_port": 443, "to_port": 443},
                                                                    {"cidr": "10.0.0.0/8", "from_port": 22, "to_port": 22}]},
                 {"id": "ssh", "type": "security_group", "ingress": [{"cidr": "0.0.0.0/0", "from_port": 20, "to_port": 25}]},
                 {"id": "all", "type": "security_group", "ingress": [{"cidr": "::/0", "from_port": 0, "to_port": 65535}]}])
        found = failing(r)
        self.assertIn(("NET-01", "ssh"), found)
        self.assertIn(("NET-02", "all"), found)
        self.assertNotIn(("NET-01", "ok"), found)

    def test_load_balancer_tls(self):
        r = run([{"id": "a", "type": "load_balancer", "allows_http": False, "min_tls": "1.0"},
                 {"id": "b", "type": "load_balancer", "allows_http": False, "min_tls": "1.3"}])
        self.assertIn(("NET-03", "a"), failing(r))
        self.assertNotIn(("NET-03", "b"), failing(r))

    def test_iam_users(self):
        r = run([{"id": "u", "type": "iam_user", "console_access": True, "mfa_enabled": False,
                  "access_key_age_days": 200, "admin_policy_direct": True},
                 {"id": "bot", "type": "iam_user", "console_access": False, "access_key_age_days": None,
                  "admin_policy_direct": False}])
        found = failing(r)
        self.assertTrue({("IAM-03", "u"), ("IAM-04", "u"), ("IAM-05", "u")} <= found)
        self.assertFalse(any(res == "bot" for _, res in found))

    def test_account_logging(self):
        r = run(account={"root_mfa": True, "root_access_keys": False, "threat_detection": True,
                         "audit_logging": {"enabled": True, "all_regions": False, "integrity_validation": True,
                                           "retention_days": 30}})
        rules = {f.check_id for f in r.findings}
        self.assertEqual(rules, {"LOG-01", "LOG-03"})

    def test_missing_data_is_not_assessed(self):
        r = run([{"id": "d", "type": "database"}])
        self.assertEqual(status(r, "DB-01"), NOT_ASSESSED)
        self.assertIsNone(r.readiness)  # nothing could be assessed, so no score is given
        self.assertEqual(r.readiness_label, "Not rated")

    def test_low_baseline_drops_moderate_only_controls(self):
        r = run([{"id": "d", "type": "database", "encrypted": False}], baseline="low")
        self.assertNotIn("DB-02", {s.check_id for s in r.checks})  # SC-28 is moderate and high


class TestSamples(unittest.TestCase):
    def test_weak_sample_not_ready(self):
        r = assess(load_inventory(WEAK))
        self.assertEqual(r.readiness_label, "Not ready")
        self.assertIn("Critical gaps", {c.status for c in r.categories})

    def test_strong_sample(self):
        r = assess(load_inventory(STRONG))
        self.assertGreaterEqual(r.readiness, 90)
        self.assertFalse(any(f.severity in ("critical", "high") for f in r.findings))

    def test_readiness_bands(self):
        self.assertEqual(readiness_label(95), "Strong")
        self.assertEqual(readiness_label(80), "Moderate gaps")
        self.assertEqual(readiness_label(60), "Significant gaps")
        self.assertEqual(readiness_label(10), "Not ready")


class TestOutput(unittest.TestCase):
    def test_writers_and_escaping(self):
        inv = load_inventory(WEAK)
        inv["organization"] = "<script>x</script>"
        r = assess(inv)
        for fmt, writer in WRITERS.items():
            self.assertTrue(writer(r).strip(), fmt)
        self.assertNotIn("<script>x</script>", WRITERS["html"](r))
        json.loads(WRITERS["json"](r))

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(main([str(WEAK), "--out", tmp, "--fail-on", "critical"]), 2)
            self.assertEqual(main([str(STRONG), "--out", tmp, "--fail-on", "high"]), 0)
            bad = Path(tmp) / "bad.json"
            bad.write_text("[]", encoding="utf-8")
            self.assertEqual(main([str(bad), "--out", tmp]), 1)


if __name__ == "__main__":
    unittest.main()
