#!/usr/bin/env python3
"""External AX correlation adapter; never grants, approves, executes or retries.

AX metadata is a caller-observed label. Opaque's authenticated broker remains the
authority. A logical run/action identity must be retained across runtime retries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

import yaml

MAX_METADATA = 64 * 1024
MAX_EXPORT = 64 * 1024 * 1024
AX_PATH = "/metadata/v1alpha1/ax/task"
IDENTIFIER = re.compile(r"[A-Za-z0-9_.:@/-]{1,128}\Z")
RESOURCE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
FIELDS = {"schema_version", "deployment_id", "atespace", "task_name", "run_id",
          "action_key", "requester_id", "scope_id", "request_id", "resource", "status",
          "issuance_round_id", "tenant_id", "broker_id", "generation"}


def identifier(value: object) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("missing or invalid correlation identifier")
    return value


def canonical_uuid(value: object) -> str:
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("run and review IDs must be canonical UUIDs")
    return value


class UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
        if any(not isinstance(key, str) for key in keys) or len(set(keys)) != len(keys):
            raise ValueError("metadata has duplicate or non-string keys")
        return super().construct_mapping(node, deep=deep)


def task_identity(data: bytes) -> tuple[str, str]:
    if len(data) > MAX_METADATA:
        raise ValueError("AX metadata exceeds 64 KiB")
    # No alias expansion, YAML merges, or custom object constructors.
    if any(isinstance(token, (yaml.AliasToken, yaml.AnchorToken)) for token in yaml.scan(data)):
        raise ValueError("AX metadata aliases are not supported")
    task = yaml.load(data, Loader=UniqueLoader)
    if not isinstance(task, dict) or task.get("apiVersion") != "ax.io/v1alpha1" or task.get("kind") != "Task":
        raise ValueError("expected an AX v1alpha1 Task")
    metadata = task.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("AX task metadata is missing")
    # Never retain spec.env, credentials, command text, or mutable task status.
    return identifier(metadata.get("atespace")), identifier(metadata.get("name"))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("AX metadata redirects are refused")


def fetch_metadata(base: str) -> bytes:
    url = urllib.parse.urlsplit(base)
    if (url.scheme != "http" or url.hostname not in {"127.0.0.1", "::1"}
            or url.username is not None or url.password is not None
            or url.path not in {"", "/"} or url.query or url.fragment):
        raise ValueError("metadata URL must name the local AX runner over HTTP")
    _ = url.port  # Reject malformed ports before creating a request.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(urllib.request.Request(base.rstrip("/") + AX_PATH, method="GET"), timeout=5) as response:
        if response.status != 200 or response.headers.get_content_type() != "application/yaml":
            raise ValueError("AX metadata response is unavailable or has the wrong format")
        data = response.read(MAX_METADATA + 1)
    if len(data) > MAX_METADATA:
        raise ValueError("AX metadata exceeds 64 KiB")
    return data


def request_id(context: dict) -> str:
    # Resource/status are deliberately excluded. Changing a proposed effect
    # under the same logical action must not quietly invent a new request ID.
    identity = ["opaque.ax.logical-action.v1", context["deployment_id"], context["atespace"],
                context["task_name"], context["run_id"], context["action_key"],
                context["requester_id"], context["scope_id"], context["tenant_id"],
                context["broker_id"], context["generation"]]
    return "ax-" + hashlib.sha256(json.dumps(identity, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def validate_context(context: object) -> dict:
    if not isinstance(context, dict) or set(context) != FIELDS or type(context["schema_version"]) is not int or context["schema_version"] != 1:
        raise ValueError("invalid correlation document")
    for field in ("deployment_id", "atespace", "task_name", "action_key", "requester_id", "scope_id", "tenant_id", "broker_id", "generation"):
        identifier(context[field])
    canonical_uuid(context["run_id"])
    canonical_uuid(context["issuance_round_id"])
    if not isinstance(context["resource"], str) or not RESOURCE.fullmatch(context["resource"]):
        raise ValueError("invalid support-case resource")
    if context["status"] not in {"open", "resolved", "closed"}:
        raise ValueError("invalid support-case status")
    if context["request_id"] != request_id(context):
        raise ValueError("correlation request ID does not match its logical action")
    return context


def bind(data: bytes, values: dict) -> tuple[dict, dict]:
    atespace, task_name = task_identity(data)
    if set(values) != FIELDS - {"schema_version", "atespace", "task_name", "request_id"}:
        raise ValueError("unexpected or missing binding fields")
    context = {"schema_version": 1, "atespace": atespace, "task_name": task_name, **values}
    context["request_id"] = request_id(context)
    validate_context(context)
    manifest = {field: context[field] for field in (
        "scope_id", "issuance_round_id", "resource", "status", "request_id")}
    return context, manifest


def document(path: Path, limit: int) -> object:
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("input exceeds its size bound")
    return json.loads(data)


def write_new(path: Path, value: object) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as target:
        json.dump(value, target, indent=2)
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())


def correlate_verified_evidence(context: dict, evidence: dict) -> dict:
    """Only call AFTER public opaque-evidence signature/semantic verification."""
    validate_context(context)
    if evidence["owner"] != {key: context[key] for key in ("tenant_id", "broker_id", "generation")}:
        raise ValueError("evidence belongs to a different authority owner")
    selected = [row for row in evidence["actions"]
                if row["action"]["request_id"] == context["request_id"]
                and row["action"]["scope_id"] == context["scope_id"]
                and row["action"]["subject"] == context["requester_id"]]
    if len(selected) > 1:
        raise ValueError("multiple actions match one logical request")
    result = {"request_id": context["request_id"], "scope_id": context["scope_id"],
              "execution": "not_observed", "disposition": "hold_for_reconciliation",
              "retry_authorized": False, "ax_identity_authenticated": False,
              "current_authority": "not_established", "provider_completion": "not_established",
              "review_signatures": "not_checked", "history": "not_checked_single_checkpoint",
              "freshness": "reference_match_only"}
    if selected:
        record = selected[0]
        action = record["action"]
        if action["resource"] != context["resource"] or action["fields"] != [{"field": "status", "value": context["status"]}]:
            raise ValueError("retained action differs from the proposed effect")
        state = record["state"]
        if state not in {"reserved", "dispatch_claimed", "api_accepted", "rejected", "unknown"}:
            raise ValueError("unsupported execution state")
        result.update({"action_id": action["action_id"], "action_digest": record["digest"],
                       "execution": state, "attempt_charged": True})
        if state == "api_accepted":
            result["disposition"] = "inspect_provider_completion"
        elif state == "rejected":
            result["disposition"] = "consumed_rejection"
    scopes = {row["grant"]["scope_id"]: row for row in evidence["scopes"]}
    scope = scopes.get(context["scope_id"])
    revoked = False if scope is not None else None
    while scope is not None:
        revoked |= scope["revoked_at"] is not None
        scope = scopes.get(scope["grant"]["parent_id"])
    result["historical_revocation"] = revoked
    return result


def inspect(args) -> dict:
    context = validate_context(document(args.context, MAX_METADATA))
    if not re.fullmatch(r"[0-9a-f]{64}", args.checkpoint_pin):
        raise ValueError("expected an independently retained checkpoint digest")
    # Verify a private copy and inspect those same bytes, never a second read of
    # the mutable input path after verification.
    import tempfile
    with args.export.open("rb") as source:
        export = source.read(MAX_EXPORT + 1)
    if len(export) > MAX_EXPORT:
        raise ValueError("scope export exceeds 64 MiB")
    with tempfile.TemporaryDirectory(prefix="opaque-ax-inspect-") as directory:
        snapshot = Path(directory) / "scope.json"
        descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(export)
        verified = subprocess.run([
            str(args.evidence_binary.resolve()), "verify", "--enrollment", str(args.enrollment),
            "--checkpoint", str(args.checkpoint), "--export", str(snapshot),
            "--expected-checkpoint-sha256", args.checkpoint_pin,
        ], capture_output=True, timeout=30, check=False)
        if verified.returncode:
            raise ValueError("public evidence verification failed; retain the hold")
    summary = json.loads(verified.stdout)
    if (summary.get("ok") is not True or summary.get("checkpoint_pin") != "matched"
            or summary.get("checkpoint_sha256") != args.checkpoint_pin
            or summary.get("evidence_format") != "scope_ledger_v1"):
        raise ValueError("verifier did not confirm the selected scope checkpoint")
    result = correlate_verified_evidence(context, json.loads(export))
    result["checkpoint_sha256"] = args.checkpoint_pin
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("bind", help="create a proposed action and correlation record; no broker mutation")
    source = create.add_mutually_exclusive_group()
    source.add_argument("--task-file", type=Path)
    source.add_argument("--metadata-url", default=None)
    for name in ("deployment-id", "run-id", "action-key", "requester-id", "scope-id", "issuance-round-id", "resource", "status", "tenant-id", "broker-id", "generation"):
        create.add_argument("--" + name, required=True)
    create.add_argument("--output", required=True, type=Path)
    query = commands.add_parser("inspect", help="verify a signed historical export and preserve unresolved work as a hold")
    for name in ("context", "enrollment", "checkpoint", "export", "evidence-binary"):
        query.add_argument("--" + name, required=True, type=Path)
    query.add_argument("--checkpoint-pin", required=True)
    args = parser.parse_args()
    try:
        if args.command == "bind":
            if args.task_file:
                with args.task_file.open("rb") as file:
                    data = file.read(MAX_METADATA + 1)
            else:
                data = fetch_metadata(args.metadata_url or os.environ.get("AX_METADATA_URL", ""))
            values = {name: getattr(args, name) for name in (
                "deployment_id", "run_id", "action_key", "requester_id", "scope_id", "issuance_round_id", "resource", "status", "tenant_id", "broker_id", "generation")}
            context, manifest = bind(data, values)
            args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
            write_new(args.output / "correlation.json", context)
            write_new(args.output / "action.json", manifest)
            print(json.dumps({"request_id": context["request_id"], "disposition": "awaiting_broker_review",
                              "authority_granted": False, "output": str(args.output)}))
        else:
            print(json.dumps(inspect(args), indent=2))
    except (OSError, ValueError, KeyError, TypeError, RecursionError, yaml.YAMLError, subprocess.SubprocessError) as error:
        # Never echo supplied metadata, command text, credentials or failed RPC bodies.
        print(json.dumps({"disposition": "hold", "retry_authorized": False, "error_type": type(error).__name__}), file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
