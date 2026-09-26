"""Correlation/display fixtures. check_runtime.py exercises actual binaries."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import adapter

TASK = b"apiVersion: ax.io/v1alpha1\nkind: Task\nmetadata:\n  name: support\n  atespace: demo\nspec:\n  env:\n    - name: TOKEN\n      value: synthetic-do-not-retain\n"


def values():
    return dict(deployment_id="local-test", run_id="00000000-0000-4000-8000-000000000001",
                action_key="case-resolution-1", requester_id="synthetic-requester", scope_id="shared-run",
                issuance_round_id="00000000-0000-4000-8000-000000000002", resource="case-1", status="resolved",
                tenant_id="synthetic-tenant", broker_id="synthetic-broker", generation="1")


def evidence(context, state="unknown"):
    return {"owner": {key: context[key] for key in ("tenant_id", "broker_id", "generation")},
            "scopes": [{"grant": {"scope_id": context["scope_id"], "parent_id": None}, "revoked_at": 100}],
            "actions": [{"action": {"request_id": context["request_id"], "scope_id": context["scope_id"],
                         "subject": context["requester_id"], "resource": context["resource"],
                         "fields": [{"field": "status", "value": context["status"]}], "action_id": "action-1"},
                         "state": state, "digest": "a" * 64}]}


class AdapterTests(unittest.TestCase):
    def test_metadata_status_changes_do_not_create_a_new_logical_request(self):
        context, manifest = adapter.bind(TASK, values())
        changed, _ = adapter.bind(TASK + b"status:\n  phase: Running\n  id: replacement-container\n", values())
        self.assertEqual(context, changed)
        self.assertEqual(len(manifest["request_id"]), 67)
        self.assertNotIn("TOKEN", json.dumps(context))
        self.assertNotIn("synthetic-do-not-retain", json.dumps(context))
        for field in ("action_key", "scope_id", "requester_id", "deployment_id", "broker_id"):
            updated = {**values(), field: "different"}
            other, _ = adapter.bind(TASK, updated)
            self.assertNotEqual(context["request_id"], other["request_id"])

    def test_changing_effect_keeps_identity_and_is_detected_against_retained_action(self):
        context, _ = adapter.bind(TASK, values())
        changed, _ = adapter.bind(TASK, {**values(), "status": "closed"})
        self.assertEqual(context["request_id"], changed["request_id"])
        with self.assertRaises(ValueError):
            adapter.correlate_verified_evidence(changed, evidence(context))

    def test_missing_or_consumed_outcomes_never_authorize_retry(self):
        context, _ = adapter.bind(TASK, values())
        for state in ("unknown", "reserved", "dispatch_claimed", "api_accepted", "rejected"):
            result = adapter.correlate_verified_evidence(context, evidence(context, state))
            self.assertFalse(result["retry_authorized"])
            self.assertTrue(result["attempt_charged"])
            self.assertTrue(result["historical_revocation"])
            self.assertEqual(result["execution"], state)
        empty = evidence(context)
        empty["actions"] = []
        empty["scopes"] = []
        result = adapter.correlate_verified_evidence(context, empty)
        self.assertEqual(result["execution"], "not_observed")
        self.assertEqual(result["disposition"], "hold_for_reconciliation")
        self.assertIsNone(result["historical_revocation"])

    def test_owner_and_identity_confusion_fail_closed(self):
        context, _ = adapter.bind(TASK, values())
        foreign = evidence(context)
        foreign["owner"]["tenant_id"] = "other"
        with self.assertRaises(ValueError):
            adapter.correlate_verified_evidence(context, foreign)
        forged = {**context, "task_name": "another-task"}
        with self.assertRaises(ValueError):
            adapter.validate_context(forged)
        duplicate = evidence(context)
        duplicate["actions"] *= 2
        with self.assertRaises(ValueError):
            adapter.correlate_verified_evidence(context, duplicate)

    def test_invalid_metadata_fails_before_any_output(self):
        for data in (b"", TASK.replace(b"Task", b"Workspace"), TASK.replace(b"atespace: demo", b"atespace: ''"),
                     TASK + b"metadata: {name: replacement, atespace: demo}\n",
                     TASK + b"unused: &a [*a]\n", b"x" * (adapter.MAX_METADATA + 1)):
            with self.subTest(data_length=len(data)), self.assertRaises((ValueError, adapter.yaml.YAMLError)):
                adapter.task_identity(data)

    def test_nonlocal_metadata_urls_are_refused_before_network(self):
        for url in ("https://127.0.0.1", "http://metadata.google.internal", "http://169.254.169.254",
                    "http://example.com", "http://user@127.0.0.1", "http://127.0.0.1/?token=x",
                    "http://127.0.0.1/custom", "http://127.0.0.1:bad"):
            with self.subTest(url=url), patch.object(adapter.urllib.request, "build_opener") as network:
                with self.assertRaises(ValueError):
                    adapter.fetch_metadata(url)
                network.assert_not_called()

    def test_context_rejects_new_fields_and_malformed_run_identity(self):
        context, _ = adapter.bind(TASK, values())
        for changed in ({**context, "approved": True}, {**context, "run_id": "new-on-every-retry"},
                        {**context, "schema_version": True}):
            with self.assertRaises(ValueError):
                adapter.validate_context(changed)
        with self.assertRaises(ValueError):
            adapter.bind(TASK, {**values(), "atespace": "overridden"})

    def test_new_files_never_overwrite_prior_context(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "context.json"
            adapter.write_new(path, {"original": True})
            with self.assertRaises(FileExistsError):
                adapter.write_new(path, {"replacement": True})
            self.assertEqual(json.loads(path.read_text()), {"original": True})


if __name__ == "__main__":
    unittest.main()
