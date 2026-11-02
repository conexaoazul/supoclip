"""Offline tests for Conexao Azul QA preflight; no network, secrets, or services."""

import importlib.util
import json
import pathlib
import unittest

BASE = pathlib.Path(__file__).resolve().parents[1]
path = BASE / "qa_preflight.py"
spec = importlib.util.spec_from_file_location("ca_supoclip_qa_preflight", path)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def valid_evidence():
    value = json.loads((BASE / "qa-evidence-template.json").read_text(encoding="utf8"))
    for key in guard.REQUIRED_TRUE:
        value[key] = True
    for key in guard.REQUIRED_FALSE:
        value[key] = False
    return value


class QaPreflightTest(unittest.TestCase):
    def test_template_denied_until_verified(self):
        value = json.loads((BASE / "qa-evidence-template.json").read_text(encoding="utf8"))
        self.assertIn("self_host", guard.validate_evidence(value))
        self.assertIn("egress_policy_verified", guard.validate_evidence(value))

    def test_synthetic_claims_pass_not_attestation(self):
        self.assertEqual(guard.validate_evidence(valid_evidence()), [])

    def test_unsigned_auth_denied(self):
        data = valid_evidence()
        data["allow_unsigned_backend_auth"] = True
        self.assertIn("allow_unsigned_backend_auth", guard.validate_evidence(data))

    def test_prod_and_public_ingress_denied(self):
        data = valid_evidence()
        data["environment"] = "production"
        data["bound_to_loopback"] = False
        data["production_network_attached"] = True
        findings = guard.validate_evidence(data)
        self.assertIn("environment", findings)
        self.assertIn("bound_to_loopback", findings)
        self.assertIn("production_network_attached", findings)

    def test_social_publication_denied(self):
        data = valid_evidence()
        data["social_publish_runtime_blocked"] = False
        data["social_account_count"] = 1
        findings = guard.validate_evidence(data)
        self.assertIn("social_publish_runtime_blocked", findings)
        self.assertIn("social_account_count", findings)

    def test_quotas_and_boolean_bypass_denied(self):
        for field, value in (("max_upload_bytes", 1000000001),
                             ("max_video_duration_seconds", 1801),
                             ("max_clips", 11),
                             ("worker_concurrency", 0),
                             ("worker_concurrency", 2),
                             ("social_account_count", False)):
            with self.subTest(field=field, value=value):
                data = valid_evidence()
                data[field] = value
                self.assertIn(field, guard.validate_evidence(data))

    def test_database_and_egress_denied(self):
        data = valid_evidence()
        data["isolated_postgres"] = False
        data["production_db_connected"] = True
        data["egress_policy_verified"] = False
        findings = guard.validate_evidence(data)
        self.assertIn("isolated_postgres", findings)
        self.assertIn("production_db_connected", findings)
        self.assertIn("egress_policy_verified", findings)

    def test_unpinned_branch_denied(self):
        data = valid_evidence()
        data["pinned_commit"] = "main"
        self.assertIn("pinned_commit", guard.validate_evidence(data))

    def test_nonobject_denied(self):
        self.assertIn("snapshot_not_object", guard.validate_evidence([]))


if __name__ == "__main__":
    unittest.main()
