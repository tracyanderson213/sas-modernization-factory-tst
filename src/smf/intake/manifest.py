"""Immutable publication, replay verification, and derived recovery for intake."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from smf.discovery import discover_source
from smf.intake.engine import manifest_digest, verify_manifest_envelope
from smf.intake.policy import IntakePolicy, verify_intake_policy
from smf.intake.schema import validate_result
from smf.intake.telemetry import intake_telemetry
from smf.readiness.policy import digest_value
from smf.workload.identity import stable_id
from smf.workload.lineage import (
    LineageArtifact,
    LineageOperation,
    RunLineage,
    build_run_lineage,
    publish_run_lineage,
)

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MEANINGFUL_SAS = re.compile(
    r"(?is)(?:^|;)\s*(?:(?:data\s+[A-Za-z_%][\w.%]*|proc\s+[A-Za-z][\w]*)"
    r"\b[^;]*;.*?(?:run|quit)\s*;|%macro\s+[A-Za-z_%][\w%]*\b.*?%mend\s*;)"
)


@dataclass(frozen=True)
class VerifiedIntakeSource:
    script_id: str
    logical_path: str
    sha256: str
    data: bytes


@dataclass(frozen=True)
class VerifiedIntakeWorkload:
    workload_id: str
    workload_revision_id: str
    closure_digest: str
    run_id: str
    attempt_id: str
    sources: tuple[VerifiedIntakeSource, ...]


def build_intake_run_lineage(
    payload: dict[str, Any], *, workload_id: str, trusted_policy: IntakePolicy
) -> RunLineage:
    """Build the canonical lineage projection for one verified admitted workload."""

    matches = [item for item in payload["decisions"] if item["workload_id"] == workload_id]
    if len(matches) != 1 or matches[0]["state"] != "admitted":
        raise ValueError("Batch intake must contain one admitted workload identity")
    decision = matches[0]
    manifest = payload["manifest_snapshot"]
    workload_matches = [
        item for item in manifest["workloads"] if item["alias"] == decision["workload_alias"]
    ]
    if len(workload_matches) != 1:
        raise ValueError("Batch intake workload alias is ambiguous")
    workload = workload_matches[0]
    artifacts = {item["script_id"]: item for item in manifest["artifacts"]}
    closure = []
    for script_id in workload["closure_ids"]:
        artifact = artifacts.get(script_id)
        if artifact is None:
            raise ValueError("Batch intake lineage source closure is incomplete")
        closure.append(
            LineageArtifact(
                subject_id=script_id,
                kind=artifact["kind"],
                logical_path=artifact["logical_path"],
                sha256=artifact["sha256"],
                size_bytes=artifact["size_bytes"],
                entrypoint=script_id in workload["entrypoint_ids"],
                source_locators=(artifact["source_uri"],),
            )
        )
    strategy_digest = digest_value(
        {
            "provider": trusted_policy.payload["provider"],
            "provider_version": trusted_policy.payload["provider_version"],
            "discovery_strategy_version": trusted_policy.payload["discovery_strategy_version"],
        }
    )
    return build_run_lineage(
        client_id=payload["client_id"],
        workload_key=decision["workload_alias"],
        artifacts=closure,
        operation=LineageOperation.INTAKE,
        target="offline-factory",
        policy_digest=payload["policy_digest"],
        strategy_digest=strategy_digest,
        configuration_digest=payload["manifest_digest"],
        idempotency_key=payload["run_id"],
        attempt_key=payload["attempt_id"],
        provider=trusted_policy.payload["provider"],
        provider_version=trusted_policy.payload["provider_version"],
        qualified_input_digests=[item.sha256 for item in closure],
    )


def _component(value: str) -> str:
    if not _SAFE_ID.fullmatch(value) or value in {".", ".."}:
        raise ValueError("Unsafe batch intake identity")
    return value


def result_path(root: Path, payload: dict[str, Any]) -> Path:
    return (
        root
        / "runs"
        / _component(payload["run_id"])
        / "batch-intakes"
        / _component(payload["batch_id"])
        / "revisions"
        / _component(payload["batch_revision_id"])
        / "attempts"
        / _component(payload["attempt_id"])
        / "intake.result.json"
    )


def _publish(path: Path, payload: dict[str, Any]) -> None:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() == encoded:
            return
        raise FileExistsError("Conflicting immutable batch intake evidence")
    descriptor, name = tempfile.mkstemp(prefix=".batch-intake-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != encoded:
                raise FileExistsError("Conflicting immutable batch intake evidence") from None
    finally:
        temporary.unlink(missing_ok=True)


def _validate(root: Path, payload: dict[str, Any], trusted_policy: IntakePolicy) -> None:
    verify_intake_policy(trusted_policy)
    validate_result(payload)
    if payload["content_digest"] != digest_value({**payload, "content_digest": ""}):
        raise ValueError("Batch intake result content digest mismatch")
    if (
        payload["policy_digest"] != trusted_policy.policy_digest
        or payload["policy_snapshot"] != trusted_policy.payload
    ):
        raise ValueError("Batch intake trusted policy binding mismatch")
    manifest = payload["manifest_snapshot"]
    verify_manifest_envelope(manifest, trusted_policy)
    top_bindings = {
        "client_id": manifest["client_id"],
        "batch_id": manifest["batch_id"],
        "batch_version": manifest["batch_version"],
        "expected_script_count": manifest["expected_script_count"],
        "policy_id": trusted_policy.payload["policy_id"],
        "policy_version": trusted_policy.payload["policy_version"],
    }
    if any(payload[key] != value for key, value in top_bindings.items()):
        raise ValueError("Batch intake envelope binding mismatch")
    if payload["manifest_digest"] != manifest_digest(manifest):
        raise ValueError("Batch intake manifest snapshot digest mismatch")
    expected_revision = stable_id(
        "BREV",
        {"manifest_digest": payload["manifest_digest"], "policy_digest": payload["policy_digest"]},
    )
    if payload["batch_revision_id"] != expected_revision:
        raise ValueError("Batch intake revision identity mismatch")
    expected_result = stable_id(
        "BINT",
        {
            "batch_revision_id": expected_revision,
            "run_id": payload["run_id"],
            "attempt_id": payload["attempt_id"],
        },
    )
    if payload["result_id"] != expected_result:
        raise ValueError("Batch intake result identity mismatch")
    workloads = manifest["workloads"]
    artifacts = {item["script_id"]: item for item in manifest["artifacts"]}
    inventory_ids = {item["script_id"] for item in manifest["artifacts"]}
    unprocessable_ids = {item["script_id"] for item in manifest["unprocessable"]}
    mapped_ids = {script_id for workload in workloads for script_id in workload["closure_ids"]}
    unassigned_ids = sorted(inventory_ids - mapped_ids)
    expected_unassigned = [
        {"script_id": script_id, "reason_code": "unmapped_inventory_script"}
        for script_id in unassigned_ids
    ]
    denominator = len(inventory_ids | unprocessable_ids)
    denominator_reconciled = (
        denominator == manifest["expected_script_count"]
        and not inventory_ids.intersection(unprocessable_ids)
        and len(manifest["artifacts"]) == len(inventory_ids)
        and len(manifest["unprocessable"]) == len(unprocessable_ids)
        and not unassigned_ids
    )
    if (
        payload["observed_unique_script_count"] != denominator
        or payload["denominator_reconciled"] is not denominator_reconciled
        or payload["unprocessable_count"] != len(unprocessable_ids)
        or payload["unassigned_scripts"] != expected_unassigned
    ):
        raise ValueError("Batch intake denominator binding mismatch")
    if len(payload["decisions"]) != len(workloads):
        raise ValueError("Batch intake workload decision total mismatch")
    admitted = 0
    blocked = 0
    for workload, decision in zip(workloads, payload["decisions"], strict=True):
        expected_workload_id = stable_id(
            "WL", {"namespace": payload["client_id"], "name": workload["alias"]}
        )
        if (
            decision["workload_alias"] != workload["alias"]
            or decision["workload_id"] != expected_workload_id
        ):
            raise ValueError("Batch intake workload identity mismatch")
        flags = decision["telemetry"]
        if decision["state"] == "admitted":
            admitted += 1
            if (
                not flags["source_admitted"]
                or flags["blocked"]
                or any(
                    flags[key]
                    for key in ("generated", "executed", "validated", "parity_passed", "certified")
                )
            ):
                raise ValueError("Batch intake telemetry claim is not authorized")
            closure = []
            for script_id in workload["closure_ids"]:
                item = artifacts.get(script_id)
                if item is None:
                    raise ValueError("Admitted intake closure is incomplete")
                closure.append(
                    {
                        "script_id": item["script_id"],
                        "logical_path": item["logical_path"],
                        "sha256": item["sha256"],
                        "size_bytes": item["size_bytes"],
                        "kind": item["kind"],
                    }
                )
            closure.sort(key=lambda item: item["script_id"])
            closure_digest = digest_value(closure)
            expected_workload_revision = stable_id(
                "WREV",
                {
                    "workload_id": expected_workload_id,
                    "closure_digest": closure_digest,
                    "manifest_version": payload["batch_version"],
                    "policy_digest": payload["policy_digest"],
                    "provider": trusted_policy.payload["provider"],
                    "provider_version": trusted_policy.payload["provider_version"],
                    "discovery_strategy_version": trusted_policy.payload[
                        "discovery_strategy_version"
                    ],
                },
            )
            if (
                decision["closure_digest"] != closure_digest
                or decision["workload_revision_id"] != expected_workload_revision
                or decision["blockers"]
            ):
                raise ValueError("Admitted intake decision binding mismatch")
            expected_refs = {
                (item["script_id"], item["logical_path"], item["sha256"], item["size_bytes"])
                for item in closure
            }
            actual_refs = {
                (
                    item.get("script_id"),
                    item.get("logical_path"),
                    item.get("sha256"),
                    item.get("size_bytes"),
                )
                for item in decision["snapshot_refs"]
            }
            if actual_refs != expected_refs or len(actual_refs) != len(decision["snapshot_refs"]):
                raise ValueError("Batch intake snapshot closure binding mismatch")
            entrypoints = set(workload["entrypoint_ids"])
            meaningful = False
            expected_snapshot_root = (
                root
                / "runs"
                / payload["run_id"]
                / "batch-intakes"
                / payload["batch_id"]
                / "revisions"
                / payload["batch_revision_id"]
                / "attempts"
                / payload["attempt_id"]
                / "workloads"
                / expected_workload_id
                / "source"
            )
            for item in decision["snapshot_refs"]:
                path = (root / item["snapshot_uri"]).resolve()
                expected_path = (expected_snapshot_root / item["logical_path"]).resolve()
                if (
                    path != expected_path
                    or not path.is_relative_to(expected_snapshot_root.resolve())
                    or not path.is_file()
                    or path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
                ):
                    raise ValueError("Batch intake snapshot is missing or unsafe")
                data = path.read_bytes()
                if (
                    len(data) != item["size_bytes"]
                    or hashlib.sha256(data).hexdigest() != item["sha256"]
                ):
                    raise ValueError("Batch intake snapshot bytes changed")
                if item["script_id"] in entrypoints:
                    source_artifact = artifacts[item["script_id"]]
                    if source_artifact["kind"] != "sas_program":
                        raise ValueError("Admitted entry point is not a SAS program")
                    try:
                        meaningful = meaningful or bool(_MEANINGFUL_SAS.search(data.decode()))
                    except UnicodeDecodeError as exc:
                        raise ValueError("Admitted entry point is not UTF-8") from exc
            if not meaningful:
                raise ValueError("Admitted intake has no meaningful SAS entry point")
            discovery = json.loads(json.dumps(decision["discovery"]))
            readiness = json.loads(json.dumps(decision["readiness_input"]))
            replayed_discovery = json.loads(
                json.dumps(
                    discover_source(
                        expected_snapshot_root,
                        provider=trusted_policy.payload["provider"],
                        namespace=payload["client_id"],
                        logical_name=workload["alias"],
                        source_locator=(
                            f"intake://{payload['batch_revision_id']}/"
                            f"{expected_workload_id}/{expected_workload_revision}"
                        ),
                    )
                    .workloads[0]
                    .to_dict()
                )
            )
            replayed_artifacts = {
                item["logical_path"]: item
                for item in replayed_discovery["artifacts"]
                if item.get("checksum")
            }
            expected_artifact_ids = [
                replayed_artifacts[item["logical_path"]]["artifact_id"] for item in closure
            ]
            expected_entrypoint_ids = [
                replayed_artifacts[artifacts[item]["logical_path"]]["artifact_id"]
                for item in workload["entrypoint_ids"]
            ]
            expected_prerequisites = [
                {"kind": item["kind"], "state": "missing", "owner": item["owner"]}
                for item in trusted_policy.payload["readiness_prerequisites"]
            ]
            expected_readiness = {
                "schema_version": "1.0",
                "client_id": payload["client_id"],
                "batch_revision_id": payload["batch_revision_id"],
                "workload_id": expected_workload_id,
                "workload_revision_id": expected_workload_revision,
                "closure_digest": closure_digest,
                "run_id": payload["run_id"],
                "attempt_id": payload["attempt_id"],
                "policy_digest": payload["policy_digest"],
                "snapshot_refs": decision["snapshot_refs"],
                "prerequisites": expected_prerequisites,
                "workload": replayed_discovery,
                "authorizes_readiness": False,
            }
            if (
                discovery != replayed_discovery
                or readiness != expected_readiness
                or decision["artifact_ids"] != expected_artifact_ids
                or decision["entrypoint_artifact_ids"] != expected_entrypoint_ids
            ):
                raise ValueError("Batch intake canonical projection binding mismatch")
            unresolved = (discovery.get("dependency_graph") or {}).get("unresolved", [])
            if any(item.get("domain") == "code" for item in unresolved if isinstance(item, dict)):
                raise ValueError("Admitted intake contains unresolved code dependencies")
        else:
            blocked += 1
            if (
                flags["source_admitted"]
                or not flags["blocked"]
                or decision["workload_revision_id"] is not None
                or decision["snapshot_refs"]
                or decision["discovery"] is not None
                or decision["readiness_input"] is not None
            ):
                raise ValueError("Blocked intake decision has invalid evidence")
    if admitted != payload["admitted_count"] or blocked != payload["blocked_count"]:
        raise ValueError("Batch intake admitted total mismatch")
    expected_disposition = (
        "admitted"
        if admitted and not blocked and denominator_reconciled and not unprocessable_ids
        else ("partial" if admitted else "blocked")
    )
    if payload["disposition"] != expected_disposition:
        raise ValueError("Batch intake disposition mismatch")


def load_intake_result(
    path: Path, *, output_root: Path, trusted_policy: IntakePolicy
) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Batch intake result must be an object")
    _validate(output_root, raw, trusted_policy)
    return raw


def write_intake_result(
    root: Path, payload: dict[str, Any], *, trusted_policy: IntakePolicy
) -> Path:
    _validate(root, payload, trusted_policy)
    path = result_path(root, payload)
    if not path.parent.resolve().is_relative_to(root.resolve()):
        raise ValueError("Batch intake output escapes root")
    _publish(path, payload)
    canonical = load_intake_result(path, output_root=root, trusted_policy=trusted_policy)
    for decision in canonical["decisions"]:
        if decision["state"] != "admitted":
            continue
        lineage = build_intake_run_lineage(
            canonical,
            workload_id=decision["workload_id"],
            trusted_policy=trusted_policy,
        )
        publish_run_lineage(root, lineage)
        projection = decision["readiness_input"]
        target = (
            path.parent / "workloads" / _component(decision["workload_id"]) / "readiness-input.json"
        )
        _publish(target, projection)
    _publish(path.with_name("intake.telemetry.json"), intake_telemetry(canonical))
    return path


def verify_intake_workload(
    path: Path,
    *,
    output_root: Path,
    trusted_policy: IntakePolicy,
    workload_id: str,
    workload_revision_id: str,
    closure_digest: str,
    run_id: str,
    attempt_id: str,
) -> VerifiedIntakeWorkload:
    payload = load_intake_result(path, output_root=output_root, trusted_policy=trusted_policy)
    if payload["run_id"] != run_id or payload["attempt_id"] != attempt_id:
        raise ValueError("Batch intake run or attempt binding mismatch")
    matches = [item for item in payload["decisions"] if item["workload_id"] == workload_id]
    if len(matches) != 1:
        raise ValueError("Batch intake must contain exactly one requested workload identity")
    decision = matches[0]
    if (
        decision["state"] != "admitted"
        or decision["workload_revision_id"] != workload_revision_id
        or decision["closure_digest"] != closure_digest
    ):
        raise ValueError("Batch intake workload binding mismatch")
    sources: list[VerifiedIntakeSource] = []
    for reference in decision["snapshot_refs"]:
        snapshot = (output_root / reference["snapshot_uri"]).resolve()
        data = snapshot.read_bytes()
        if (
            len(data) != reference["size_bytes"]
            or hashlib.sha256(data).hexdigest() != reference["sha256"]
        ):
            raise ValueError("Batch intake source changed during verified handoff")
        sources.append(
            VerifiedIntakeSource(
                script_id=reference["script_id"],
                logical_path=reference["logical_path"],
                sha256=reference["sha256"],
                data=data,
            )
        )
    return VerifiedIntakeWorkload(
        workload_id=decision["workload_id"],
        workload_revision_id=decision["workload_revision_id"],
        closure_digest=decision["closure_digest"],
        run_id=payload["run_id"],
        attempt_id=payload["attempt_id"],
        sources=tuple(sources),
    )
