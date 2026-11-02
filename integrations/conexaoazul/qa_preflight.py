"""Offline lint of QA evidence snapshots. Never reads secrets or calls the network.

IMPORTANT: a PASS only verifies that the *claims* satisfy the policy.
It cannot attest that runtime controls actually exist. No deployment actions.
"""

import json
import pathlib
import sys

PINNED_SHA = "4bc76f83b3427808464f117473ee61083c65cf1f"
REQUIRED_TRUE = (
    "self_host", "backend_cpu_only", "signup_disabled", "bound_to_loopback",
    "isolated_postgres", "isolated_redis", "storage_private",
    "egress_policy_verified", "social_publish_runtime_blocked",
    "qa_scoped_credentials_verified", "source_rights_evidence_verified",
    "legal_review_completed",
)
REQUIRED_FALSE = (
    "allow_unsigned_backend_auth", "production_network_attached",
    "production_db_connected",
)
LIMITS = {
    "social_account_count": (0, 0),
    "worker_concurrency": (1, 1),
    "max_video_duration_seconds": (1, 1800),
    "max_upload_bytes": (1, 1000000000),
    "max_clips": (1, 10),
}


def validate_evidence(snapshot):
    """Return safe errors only, never values of arbitrary snapshot keys."""
    if not isinstance(snapshot, dict):
        return ["snapshot_not_object"]
    errors = []
    if snapshot.get("schema_version") != "1":
        errors.append("schema_version")
    if snapshot.get("source_repo") != "conexaoazul/supoclip":
        errors.append("source_repo")
    if snapshot.get("pinned_commit") != PINNED_SHA:
        errors.append("pinned_commit")
    if snapshot.get("environment") != "qa":
        errors.append("environment")
    for key in REQUIRED_TRUE:
        if snapshot.get(key) is not True:
            errors.append(key)
    for key in REQUIRED_FALSE:
        if snapshot.get(key) is not False:
            errors.append(key)
    for key, (minimum, maximum) in LIMITS.items():
        value = snapshot.get(key)
        if type(value) is not int or not minimum <= value <= maximum:
            errors.append(key)
    return sorted(errors)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        print("Usage: qa_preflight.py <nonsecret-evidence.json>", file=sys.stderr)
        return 2
    path = pathlib.Path(argv[0])
    try:
        if path.stat().st_size > 64 * 1024:
            raise ValueError("oversized")
        obj = json.loads(path.read_text(encoding="utf8"))
    except (OSError, UnicodeError, ValueError):
        print("DENY: invalid or unavailable evidence snapshot")
        return 2
    failures = validate_evidence(obj)
    if failures:
        print("DENY: " + ", ".join(failures))
        return 1
    print("PRELIMINARY PASS: claimed QA controls satisfy policy; runtime evidence still required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
