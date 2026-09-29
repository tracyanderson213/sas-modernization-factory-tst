"""Deterministic physical-asset inventory from admitted static evidence only."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from smf.asset_inventory.models import (
    AssetContract,
    AssetDirection,
    AssetKind,
    AssetObservationState,
    BlockerReason,
    ContractState,
    DeliveryReceipt,
    FixtureRoot,
    InventoryPolicy,
    InventoryRequest,
)
from smf.discovery.lineage import derive_data_lineage
from smf.security.ai_admission import contains_protected_data
from smf.workload.identity import stable_id
from smf.workload.models import DatasetKind, RelationshipKind
from smf.workload.sanitization import sanitize_discovery_value

FIXTURE_MARKER = b"SMF synthetic fixture root v1\n"
PRODUCTION_AUTHORIZED_ROOTS: tuple[Path, ...] = ()
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAS_SUFFIXES = {
    ".sas7bdat": AssetKind.SAS_DATASET,
    ".sas7bcat": AssetKind.SAS_CATALOG,
    ".sas7bvew": AssetKind.SAS_VIEW,
    ".sas7bndx": AssetKind.SAS_INDEX,
    ".xpt": AssetKind.SAS_TRANSPORT,
    ".cport": AssetKind.SAS_TRANSPORT,
}


@dataclass(frozen=True)
class PreparedAssetInventory:
    result: dict[str, Any]
    projection: dict[str, Any]


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _identity(value: str, label: str) -> str:
    if (
        not _SAFE_ID.fullmatch(value)
        or value in {".", ".."}
        or sanitize_discovery_value(value) != value
    ):
        raise ValueError(f"Unsafe asset inventory {label}")
    return value


def _policy_payload(policy: InventoryPolicy) -> dict[str, Any]:
    keys = list(policy.verification_keys)
    if len({item[0] for item in keys}) != len(keys):
        raise ValueError("Duplicate verification key identity")
    authorities = [
        _identity(item, "receipt authority") for item in policy.trusted_receipt_authorities
    ]
    for key_id, encoded_key in keys:
        _identity(key_id, "verification key id")
        try:
            decoded_key = base64.b64decode(encoded_key, validate=True)
        except ValueError as exc:
            raise ValueError("Inventory verification key is malformed") from exc
        if len(decoded_key) != 32:
            raise ValueError("Inventory verification key is malformed")
    return {
        "policy_id": _identity(policy.policy_id, "policy_id"),
        "policy_version": _identity(policy.policy_version, "policy_version"),
        "client_id": _identity(policy.client_id, "client_id"),
        "trusted_receipt_authorities": sorted(authorities),
        "verification_keys": sorted([list(item) for item in keys]),
    }


def _open_root(root: Path, label: str) -> tuple[Path, int]:
    lexical = Path(os.path.abspath(os.fspath(root)))
    if root.is_symlink() or not lexical.is_dir():
        raise ValueError(f"{label} is missing or unsafe")
    resolved = lexical.resolve()
    temporary = Path(tempfile.gettempdir()).resolve()
    if resolved != lexical or not resolved.is_relative_to(temporary):
        raise ValueError(f"{label} must be under the local temporary boundary")
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lexical, flags)
    return resolved, descriptor


def _read_relative(root_fd: int, relative: PurePosixPath) -> tuple[bytes, os.stat_result]:
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError("asset path escapes fixture root")
    descriptor = os.dup(root_fd)
    try:
        for part in relative.parts[:-1]:
            component_mode = os.stat(part, dir_fd=descriptor, follow_symlinks=False).st_mode
            if stat.S_ISLNK(component_mode):
                raise ValueError("asset path contains a symlink")
            flags = os.O_RDONLY | os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            replacement = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = replacement
        flags = os.O_RDONLY | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        file_mode = os.stat(relative.name, dir_fd=descriptor, follow_symlinks=False).st_mode
        if stat.S_ISLNK(file_mode):
            raise ValueError("asset path contains a symlink")
        file_fd = os.open(relative.name, flags, dir_fd=descriptor)
        try:
            observed = os.fstat(file_fd)
            if not stat.S_ISREG(observed.st_mode):
                raise ValueError("asset is not a regular file")
            with os.fdopen(file_fd, "rb", closefd=False) as handle:
                return handle.read(), observed
        finally:
            os.close(file_fd)
    finally:
        os.close(descriptor)


def _validated_roots(roots: tuple[FixtureRoot, ...]) -> dict[str, tuple[Path, int]]:
    if len({item.root_id for item in roots}) != len(roots):
        raise ValueError("Duplicate fixture root identity")
    validated: dict[str, tuple[Path, int]] = {}
    try:
        for item in roots:
            root_id = _identity(item.root_id, "fixture root id")
            resolved, descriptor = _open_root(item.path, "Synthetic fixture root")
            try:
                marker, _ = _read_relative(descriptor, PurePosixPath(".smf-synthetic-fixture-root"))
            except (OSError, ValueError) as exc:
                os.close(descriptor)
                raise ValueError("Synthetic fixture root marker is missing or unsafe") from exc
            if marker != FIXTURE_MARKER:
                os.close(descriptor)
                raise ValueError("Synthetic fixture root marker is invalid")
            validated[root_id] = (resolved, descriptor)
        return validated
    except Exception:
        for _, descriptor in validated.values():
            os.close(descriptor)
        raise


def _source_bytes(request: InventoryRequest) -> dict[str, bytes]:
    source_root, descriptor = _open_root(request.source_root, "Source fixture root")
    del source_root
    try:
        try:
            marker, _ = _read_relative(descriptor, PurePosixPath(".smf-synthetic-fixture-root"))
        except (OSError, ValueError) as exc:
            raise ValueError("Source fixture root marker is missing or unsafe") from exc
        if marker != FIXTURE_MARKER:
            raise ValueError("Source fixture root marker is invalid")
        acquired: dict[str, bytes] = {}
        for artifact in request.workload.artifacts:
            if artifact.logical_path is None or artifact.checksum is None:
                continue
            try:
                data, _ = _read_relative(descriptor, PurePosixPath(artifact.logical_path))
            except OSError as exc:
                raise ValueError("Static source evidence is no longer available") from exc
            if hashlib.sha256(data).hexdigest() != artifact.checksum:
                raise ValueError("Static source bytes changed after qualification")
            acquired[artifact.artifact_id] = data
        return acquired
    finally:
        os.close(descriptor)


def _verify_access(access: Any, source_bytes: dict[str, bytes]) -> None:
    data = source_bytes.get(access.artifact_id)
    if data is None or hashlib.sha256(data).hexdigest() != access.source_checksum:
        raise ValueError("Asset occurrence is not bound to qualified source bytes")
    if (
        access.byte_end > len(data)
        or hashlib.sha256(data[access.byte_start : access.byte_end]).hexdigest()
        != access.span_digest
    ):
        raise ValueError("Asset occurrence span is not reconstructable")


def _validate_lineage(request: InventoryRequest, source_bytes: dict[str, bytes]) -> Any:
    admitted = request.workload.data_lineage_analysis
    if admitted is None or admitted.workload_id != request.workload.workload_id:
        raise ValueError("Admitted occurrence-bound static lineage is required")
    regenerated = derive_data_lineage(
        request.workload, artifact_bytes=source_bytes
    ).data_lineage_analysis
    if regenerated is None or regenerated != admitted:
        raise ValueError("Admitted static lineage does not match canonical occurrence evidence")
    datasets = {item.dataset_id: item for item in request.workload.datasets}
    for access in admitted.accesses:
        dataset = datasets.get(access.dataset_id)
        if dataset is None:
            raise ValueError("Asset occurrence references an unknown dataset")
        if dataset.kind is DatasetKind.FILE:
            expected_name = PurePosixPath(access.normalized_reference.replace("\\", "/")).name
            if dataset.name != expected_name:
                raise ValueError("Asset dataset name does not match occurrence identity")
    return admitted


def _kind(dataset: Any) -> AssetKind:
    suffix = PurePosixPath(dataset.location or dataset.name).suffix.lower()
    if suffix in _SAS_SUFFIXES:
        return _SAS_SUFFIXES[suffix]
    if dataset.kind is DatasetKind.SAS_DATASET:
        return AssetKind.SAS_DATASET
    if dataset.kind is DatasetKind.FILE:
        return AssetKind.FILE
    if dataset.kind is DatasetKind.EXTERNAL_FEED:
        return AssetKind.EXTERNAL_FEED
    return AssetKind.UNSUPPORTED


def _candidate(access: Any, reference: str) -> PurePosixPath:
    path = PurePosixPath(reference.replace("\\", "/"))
    if path.is_absolute():
        return PurePosixPath(*path.parts[1:])
    return PurePosixPath(access.source_path).parent / path


def _receipt_payload(receipt: DeliveryReceipt) -> dict[str, str]:
    return {
        "receipt_id": receipt.receipt_id,
        "client_id": receipt.client_id,
        "workload_id": receipt.workload_id,
        "source_closure_digest": receipt.source_closure_digest,
        "policy_digest": receipt.policy_digest,
        "run_id": receipt.run_id,
        "attempt_id": receipt.attempt_id,
        "access_id": receipt.access_id,
        "asset_sha256": receipt.asset_sha256,
        "delivered_at": receipt.delivered_at,
        "authority": receipt.authority,
        "key_id": receipt.key_id,
    }


def _verify_receipt(
    receipt: DeliveryReceipt,
    *,
    access_id: str,
    asset_sha256: str,
    policy: InventoryPolicy,
    workload_id: str,
    source_closure_digest: str,
    policy_digest: str,
    run_id: str,
    attempt_id: str,
) -> datetime:
    payload = _receipt_payload(receipt)
    expected_id = stable_id(
        "DELIVERY",
        {key: value for key, value in payload.items() if key != "receipt_id"},
    )
    expected_bindings = {
        "client_id": policy.client_id,
        "workload_id": workload_id,
        "source_closure_digest": source_closure_digest,
        "policy_digest": policy_digest,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "access_id": access_id,
    }
    if receipt.receipt_id != expected_id or any(
        getattr(receipt, key) != value for key, value in expected_bindings.items()
    ):
        raise ValueError("Delivery receipt identity binding mismatch")
    if receipt.asset_sha256 != asset_sha256 or not _SHA256.fullmatch(receipt.asset_sha256):
        raise ValueError("Delivery receipt byte binding mismatch")
    if receipt.authority not in policy.trusted_receipt_authorities:
        raise ValueError("Delivery receipt authority is not trusted")
    key_values = dict(policy.verification_keys)
    encoded_key = key_values.get(receipt.key_id)
    if encoded_key is None:
        raise ValueError("Delivery receipt key is not trusted")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded_key, validate=True))
        key.verify(base64.b64decode(receipt.signature, validate=True), canonical)
        delivered_at = datetime.fromisoformat(receipt.delivered_at)
    except (ValueError, InvalidSignature) as exc:
        raise ValueError("Delivery receipt proof is invalid") from exc
    if delivered_at.tzinfo is None:
        raise ValueError("Delivery receipt timestamp must include a timezone")
    return delivered_at.astimezone(UTC)


def _contract_fields(contract: AssetContract | None) -> tuple[dict[str, Any], list[str]]:
    blockers: list[str] = []
    if contract is not None:
        for label, value in (
            ("owner", contract.owner),
            ("cadence", contract.cadence),
            ("timezone", contract.timezone),
        ):
            if value is not None and (
                sanitize_discovery_value(value) != value or contains_protected_data(value)
            ):
                raise ValueError(f"Unsafe asset contract {label}")
        if contract.freshness_seconds is not None and contract.freshness_seconds <= 0:
            raise ValueError("Asset contract freshness must be positive")
        for missing_value, reason in (
            (contract.owner, BlockerReason.CONTRACT_OWNER_MISSING),
            (contract.cadence, BlockerReason.CONTRACT_CADENCE_MISSING),
            (contract.timezone, BlockerReason.CONTRACT_TIMEZONE_MISSING),
            (contract.freshness_seconds, BlockerReason.CONTRACT_FRESHNESS_MISSING),
        ):
            if missing_value is None or (
                isinstance(missing_value, str) and not missing_value.strip()
            ):
                blockers.append(reason.value)
    return (
        {
            "owner": contract.owner if contract else None,
            "cadence": contract.cadence if contract else None,
            "timezone": contract.timezone if contract else None,
            "freshness_seconds": contract.freshness_seconds if contract else None,
            "authority": None,
            "accessibility": None,
            "delivery_receipt_id": None,
        },
        blockers,
    )


def evaluate_asset_inventory(request: InventoryRequest) -> PreparedAssetInventory:
    """Evaluate one immutable offline inventory attempt; never contacts external systems."""

    for label in ("run_id", "attempt_id"):
        _identity(str(getattr(request, label)), label)
    policy_payload = _policy_payload(request.policy)
    policy_digest = _digest(policy_payload)
    try:
        evaluated_at = datetime.fromisoformat(request.evaluated_at)
    except ValueError as exc:
        raise ValueError("Inventory evaluation timestamp is invalid") from exc
    if evaluated_at.tzinfo is None:
        raise ValueError("Inventory evaluation timestamp must include a timezone")
    evaluated_at = evaluated_at.astimezone(UTC)
    contracts = {item.dataset_id: item for item in request.contracts}
    receipts = {item.access_id: item for item in request.receipts}
    if len(contracts) != len(request.contracts):
        raise ValueError("Duplicate asset contract identity")
    if len(receipts) != len(request.receipts):
        raise ValueError("Duplicate delivery receipt identity")
    analysis = request.workload.data_lineage_analysis
    if analysis is None or analysis.workload_id != request.workload.workload_id:
        raise ValueError("Admitted occurrence-bound static lineage is required")
    accesses = tuple(analysis.accesses)
    if len({item.access_id for item in accesses}) != len(accesses):
        raise ValueError("Duplicate asset occurrence identity")
    if any(item.role not in {RelationshipKind.READS, RelationshipKind.WRITES} for item in accesses):
        raise ValueError("Unsupported asset occurrence direction")
    dataset_ids = {item.dataset_id for item in request.workload.datasets}
    if not set(contracts).issubset(dataset_ids):
        raise ValueError("Asset contract references an unknown dataset")
    source_bytes = _source_bytes(request)
    analysis = _validate_lineage(request, source_bytes)
    accesses = tuple(analysis.accesses)
    access_ids = {item.access_id for item in accesses}
    if not set(receipts).issubset(access_ids):
        raise ValueError("Delivery receipt references an unknown occurrence")
    roots = _validated_roots(request.fixture_roots)
    try:
        datasets = {item.dataset_id: item for item in request.workload.datasets}
        if len(datasets) != len(request.workload.datasets):
            raise ValueError("Duplicate canonical dataset identity")
        items: list[dict[str, Any]] = []
        result_blockers: set[str] = set()
        eligible = 0
        for access in sorted(accesses, key=lambda item: item.access_id):
            _verify_access(access, source_bytes)
            if access.role not in {RelationshipKind.READS, RelationshipKind.WRITES}:
                raise ValueError("Unsupported asset occurrence direction")
            dataset = datasets.get(access.dataset_id)
            if dataset is None:
                raise ValueError("Asset occurrence references an unknown dataset")
            if not isinstance(dataset.kind, DatasetKind):
                raise ValueError("Unsupported asset dataset kind")
            kind = _kind(dataset)
            supported = kind is not AssetKind.UNSUPPORTED
            if supported:
                eligible += 1
            direction = (
                AssetDirection.INPUT
                if access.role is RelationshipKind.READS
                else AssetDirection.OUTPUT
            )
            reference = dataset.location or access.normalized_reference
            contract = contracts.get(dataset.dataset_id)
            fields, contract_blockers = _contract_fields(contract)
            state = AssetObservationState.PENDING
            blockers: list[str] = list(contract_blockers)
            root_id: str | None = None
            relative_path: str | None = None
            byte_count: int | None = None
            asset_sha256: str | None = None
            metadata_observation: dict[str, int] | None = None
            if not supported:
                state = AssetObservationState.UNSUPPORTED
                blockers.append(BlockerReason.ASSET_UNSUPPORTED.value)
            elif access.identity_resolution.value == "unresolved" or not reference:
                state = AssetObservationState.UNRESOLVED
                blockers.append(BlockerReason.IDENTITY_UNRESOLVED.value)
            else:
                candidate = _candidate(access, reference)
                if any(part in {"", ".", ".."} for part in candidate.parts):
                    state = AssetObservationState.BOUNDARY_BLOCKED
                    blockers.append(BlockerReason.BOUNDARY_ESCAPE.value)
                elif not roots:
                    state = AssetObservationState.PENDING
                    blockers.append(BlockerReason.AUTHORIZED_ROOT_MISSING.value)
                else:
                    observations: list[tuple[str, bytes, os.stat_result]] = []
                    inaccessible = False
                    boundary_violation = False
                    for candidate_root_id, (_, descriptor) in roots.items():
                        try:
                            data, observed_stat = _read_relative(descriptor, candidate)
                            observations.append((candidate_root_id, data, observed_stat))
                        except FileNotFoundError:
                            continue
                        except ValueError:
                            boundary_violation = True
                        except (PermissionError, OSError):
                            inaccessible = True
                    if len(observations) > 1:
                        raise ValueError("Asset path identity is ambiguous across fixture roots")
                    if observations:
                        root_id, data, observed_stat = observations[0]
                        state = AssetObservationState.OBSERVED
                        relative_path = candidate.as_posix()
                        byte_count = len(data)
                        asset_sha256 = hashlib.sha256(data).hexdigest()
                        metadata_observation = {
                            "size_bytes": observed_stat.st_size,
                            "modified_time_ns": observed_stat.st_mtime_ns,
                        }
                        fields["accessibility"] = "observed_readable"
                    elif boundary_violation:
                        state = AssetObservationState.BOUNDARY_BLOCKED
                        blockers.append(BlockerReason.BOUNDARY_ESCAPE.value)
                    elif inaccessible:
                        state = AssetObservationState.INACCESSIBLE
                        blockers.append(BlockerReason.ASSET_INACCESSIBLE.value)
                    else:
                        state = AssetObservationState.REFERENCED_MISSING
                        blockers.append(BlockerReason.REFERENCED_ASSET_MISSING.value)
            receipt = receipts.get(access.access_id)
            contract_state = ContractState.PENDING
            if state is AssetObservationState.OBSERVED and asset_sha256 is not None:
                if receipt is not None:
                    try:
                        delivered_at = _verify_receipt(
                            receipt,
                            access_id=access.access_id,
                            asset_sha256=asset_sha256,
                            policy=request.policy,
                            workload_id=request.workload.workload_id,
                            source_closure_digest=analysis.source_closure_digest,
                            policy_digest=policy_digest,
                            run_id=request.run_id,
                            attempt_id=request.attempt_id,
                        )
                    except ValueError:
                        state = AssetObservationState.DENIED
                        contract_state = ContractState.DENIED
                        blockers.append(BlockerReason.DELIVERY_RECEIPT_INVALID.value)
                    else:
                        if delivered_at > evaluated_at:
                            state = AssetObservationState.DENIED
                            contract_state = ContractState.DENIED
                            blockers.append(BlockerReason.DELIVERY_RECEIPT_INVALID.value)
                        receipt_is_stale = (
                            state is not AssetObservationState.DENIED
                            and contract is not None
                            and contract.freshness_seconds is not None
                            and (evaluated_at - delivered_at).total_seconds()
                            > contract.freshness_seconds
                        )
                        if state is not AssetObservationState.DENIED:
                            fields["authority"] = receipt.authority
                            fields["delivery_receipt_id"] = receipt.receipt_id
                        if receipt_is_stale:
                            state = AssetObservationState.STALE
                            contract_state = ContractState.BLOCKED
                            blockers.append(BlockerReason.DELIVERY_STALE.value)
                        elif (
                            state is not AssetObservationState.DENIED
                            and contract is not None
                            and not contract_blockers
                        ):
                            contract_state = ContractState.SATISFIED
                elif contract and (
                    contract.delivery_receipt_required or contract.freshness_seconds is not None
                ):
                    blockers.append(BlockerReason.DELIVERY_RECEIPT_MISSING.value)
                elif contract is None:
                    blockers.append(BlockerReason.CONTRACT_PENDING.value)
            elif state is AssetObservationState.UNSUPPORTED:
                contract_state = ContractState.UNSUPPORTED
            elif state not in {AssetObservationState.PENDING}:
                contract_state = ContractState.BLOCKED
            if contract is None and BlockerReason.CONTRACT_PENDING.value not in blockers:
                blockers.append(BlockerReason.CONTRACT_PENDING.value)
            result_blockers.update(blockers)
            item_identity = {
                "workload_id": request.workload.workload_id,
                "source_closure_digest": analysis.source_closure_digest,
                "access_id": access.access_id,
                "dataset_id": dataset.dataset_id,
                "direction": direction.value,
                "reference": reference,
                "root_id": root_id,
                "relative_path": relative_path,
                "asset_sha256": asset_sha256,
                "policy_digest": policy_digest,
                "run_id": request.run_id,
                "attempt_id": request.attempt_id,
            }
            items.append(
                {
                    "inventory_item_id": stable_id("ASSET", item_identity),
                    "access_id": access.access_id,
                    "dataset_id": dataset.dataset_id,
                    "source_artifact_id": access.artifact_id,
                    "source_checksum": access.source_checksum,
                    "span_digest": access.span_digest,
                    "source_reference": reference,
                    "kind": kind.value,
                    "direction": direction.value,
                    "observation_state": state.value,
                    "contract_state": contract_state.value,
                    "root_id": root_id,
                    "relative_path": relative_path,
                    "path_identity": _digest({"root_id": root_id, "relative_path": relative_path}),
                    "asset_sha256": asset_sha256,
                    "byte_count": byte_count,
                    "metadata_observation": metadata_observation,
                    **fields,
                    "blockers": sorted(blockers),
                    "claims": {
                        "exists": asset_sha256 is not None,
                        "fresh": (
                            contract_state is ContractState.SATISFIED
                            and fields["delivery_receipt_id"] is not None
                            and contract is not None
                            and contract.freshness_seconds is not None
                        ),
                        "authorized": fields["authority"] is not None,
                        "complete": False,
                    },
                }
            )
        if eligible == 0:
            result_blockers.add(BlockerReason.NO_ELIGIBLE_SUBJECT.value)
        identity = {
            "client_id": request.policy.client_id,
            "workload_id": request.workload.workload_id,
            "source_closure_digest": analysis.source_closure_digest,
            "policy_digest": policy_digest,
            "run_id": request.run_id,
            "attempt_id": request.attempt_id,
        }
        result: dict[str, Any] = {
            "schema_version": "1.0",
            "inventory_result_id": stable_id("BASE07", identity),
            "client_id": request.policy.client_id,
            "workload_id": request.workload.workload_id,
            "source_closure_digest": analysis.source_closure_digest,
            "policy_id": request.policy.policy_id,
            "policy_version": request.policy.policy_version,
            "policy_digest": policy_digest,
            "run_id": request.run_id,
            "attempt_id": request.attempt_id,
            "evaluated_at": evaluated_at.isoformat(),
            "production_authorized_root_count": len(PRODUCTION_AUTHORIZED_ROOTS),
            "fixture_root_ids": sorted(roots),
            "items": items,
            "blockers": sorted(result_blockers),
            "claims": {
                "inventory_generated": bool(eligible),
                "production_inventory": False,
                "executed": False,
                "validated": False,
                "parity_passed": False,
                "certified": False,
                "human_approved": False,
                "complete": False,
            },
            "content_digest": "",
        }
        result["content_digest"] = _digest({**result, "content_digest": ""})
        projection = asset_inventory_projection(result)
        return PreparedAssetInventory(result=result, projection=projection)
    finally:
        for _, descriptor in roots.values():
            os.close(descriptor)


def delivery_receipt_signing_payload(receipt: DeliveryReceipt) -> bytes:
    """Return canonical receipt bytes for fixture signers and independent verification."""

    return json.dumps(_receipt_payload(receipt), sort_keys=True, separators=(",", ":")).encode()


def asset_inventory_projection(result: dict[str, Any]) -> dict[str, Any]:
    """Derive the consumer projection from one intact canonical result."""

    if result.get("content_digest") != _digest({**result, "content_digest": ""}):
        raise ValueError("Canonical asset inventory result digest is invalid")
    items = result.get("items")
    if not isinstance(items, list):
        raise ValueError("Canonical asset inventory result items are invalid")
    valid_states = {state.value for state in AssetObservationState}
    if any(item.get("observation_state") not in valid_states for item in items):
        raise ValueError("Canonical asset inventory result state is invalid")
    return {
        "schema_version": "1.0",
        "inventory_result_id": result["inventory_result_id"],
        "content_digest": result["content_digest"],
        "workload_id": result["workload_id"],
        "run_id": result["run_id"],
        "attempt_id": result["attempt_id"],
        "item_count": len(items),
        "input_count": sum(item["direction"] == "input" for item in items),
        "output_count": sum(item["direction"] == "output" for item in items),
        "states": {
            state.value: sum(item["observation_state"] == state.value for item in items)
            for state in AssetObservationState
        },
        "blockers": result["blockers"],
        "complete": False,
    }
