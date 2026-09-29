"""Immutable models for the BASE-07 offline asset-inventory increment."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from smf.workload.models import Workload


class AssetKind(StrEnum):
    SAS_DATASET = "sas_dataset"
    SAS_CATALOG = "sas_catalog"
    SAS_VIEW = "sas_view"
    SAS_INDEX = "sas_index"
    SAS_TRANSPORT = "sas_transport"
    FILE = "file"
    EXTERNAL_FEED = "external_feed"
    CONFIGURATION = "configuration"
    UNSUPPORTED = "unsupported"


class AssetDirection(StrEnum):
    INPUT = "input"
    OUTPUT = "output"


class AssetObservationState(StrEnum):
    OBSERVED = "observed"
    REFERENCED_MISSING = "referenced_missing"
    UNRESOLVED = "unresolved"
    INACCESSIBLE = "inaccessible"
    STALE = "stale"
    DENIED = "denied"
    PENDING = "pending"
    UNSUPPORTED = "unsupported"
    BOUNDARY_BLOCKED = "boundary_blocked"


class ContractState(StrEnum):
    SATISFIED = "satisfied"
    PENDING = "pending"
    BLOCKED = "blocked"
    DENIED = "denied"
    UNSUPPORTED = "unsupported"


class BlockerReason(StrEnum):
    NO_ELIGIBLE_SUBJECT = "no_eligible_subject"
    INVALID_STATIC_EVIDENCE = "invalid_static_evidence"
    DUPLICATE_IDENTITY = "duplicate_identity"
    AUTHORIZED_ROOT_MISSING = "authorized_root_missing"
    BOUNDARY_ESCAPE = "boundary_escape"
    REFERENCED_ASSET_MISSING = "referenced_asset_missing"
    ASSET_INACCESSIBLE = "asset_inaccessible"
    IDENTITY_UNRESOLVED = "identity_unresolved"
    ASSET_UNSUPPORTED = "asset_unsupported"
    CONTRACT_PENDING = "contract_pending"
    CONTRACT_OWNER_MISSING = "contract_owner_missing"
    CONTRACT_CADENCE_MISSING = "contract_cadence_missing"
    CONTRACT_TIMEZONE_MISSING = "contract_timezone_missing"
    CONTRACT_FRESHNESS_MISSING = "contract_freshness_missing"
    DELIVERY_RECEIPT_MISSING = "delivery_receipt_missing"
    DELIVERY_RECEIPT_INVALID = "delivery_receipt_invalid"
    DELIVERY_STALE = "delivery_stale"


@dataclass(frozen=True)
class FixtureRoot:
    root_id: str
    path: Path


@dataclass(frozen=True)
class AssetContract:
    dataset_id: str
    owner: str | None = None
    cadence: str | None = None
    timezone: str | None = None
    freshness_seconds: int | None = None
    delivery_receipt_required: bool = False


@dataclass(frozen=True)
class DeliveryReceipt:
    receipt_id: str
    client_id: str
    workload_id: str
    source_closure_digest: str
    policy_digest: str
    run_id: str
    attempt_id: str
    access_id: str
    asset_sha256: str
    delivered_at: str
    authority: str
    key_id: str
    signature: str


@dataclass(frozen=True)
class InventoryPolicy:
    policy_id: str
    policy_version: str
    client_id: str
    trusted_receipt_authorities: tuple[str, ...] = ()
    verification_keys: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class InventoryRequest:
    workload: Workload
    source_root: Path
    fixture_roots: tuple[FixtureRoot, ...]
    contracts: tuple[AssetContract, ...]
    receipts: tuple[DeliveryReceipt, ...]
    policy: InventoryPolicy
    run_id: str
    attempt_id: str
    evaluated_at: str
