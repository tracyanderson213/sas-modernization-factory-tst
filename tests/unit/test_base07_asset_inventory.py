from __future__ import annotations

import base64
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.asset_inventory import (
    AssetContract,
    DeliveryReceipt,
    FixtureRoot,
    InventoryPolicy,
    InventoryRequest,
    evaluate_asset_inventory,
    publish_asset_inventory,
)
from smf.asset_inventory.engine import FIXTURE_MARKER, delivery_receipt_signing_payload
from smf.asset_inventory.telemetry import asset_inventory_event
from smf.discovery import discover_source
from smf.workload.identity import stable_id
from smf.workload.models import DatasetKind, RelationshipKind


def _fixture(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / ".smf-synthetic-fixture-root").write_bytes(FIXTURE_MARKER)


def _request(
    root: Path,
    source: str,
    *,
    contracts: tuple[AssetContract, ...] = (),
    receipts: tuple[DeliveryReceipt, ...] = (),
    policy: InventoryPolicy | None = None,
    run_id: str = "run-1",
    attempt_id: str = "attempt-1",
    evaluated_at: str = "2026-09-19T12:00:00+00:00",
) -> InventoryRequest:
    _fixture(root)
    (root / "job.sas").write_text(source, encoding="utf-8")
    workload = discover_source(root, provider="filesystem", namespace="base07").workloads[0]
    return InventoryRequest(
        workload=workload,
        source_root=root,
        fixture_roots=(FixtureRoot("fixture-a", root),),
        contracts=contracts,
        receipts=receipts,
        policy=policy or InventoryPolicy("base07", "1", "synthetic-client"),
        run_id=run_id,
        attempt_id=attempt_id,
        evaluated_at=evaluated_at,
    )


def test_inventory_separates_input_output_and_does_not_infer_input_exists(
    tmp_path: Path,
) -> None:
    root = tmp_path / "fixture"
    _fixture(root)
    (root / "out.csv").write_text("generated", encoding="utf-8")
    request = _request(
        root,
        'data _null_; infile "missing.csv"; file "out.csv"; run;\n',
    )

    prepared = evaluate_asset_inventory(request)
    by_direction = {item["direction"]: item for item in prepared.result["items"]}

    assert by_direction["input"]["observation_state"] == "referenced_missing"
    assert by_direction["input"]["claims"]["exists"] is False
    assert by_direction["output"]["observation_state"] == "observed"
    assert by_direction["output"]["asset_sha256"]
    assert prepared.result["claims"] == {
        "inventory_generated": True,
        "production_inventory": False,
        "executed": False,
        "validated": False,
        "parity_passed": False,
        "certified": False,
        "human_approved": False,
        "complete": False,
    }
    assert prepared.result["production_authorized_root_count"] == 0


def test_relative_paths_are_source_scoped_and_boundary_escape_is_blocked(
    tmp_path: Path,
) -> None:
    root = tmp_path / "fixture"
    _fixture(root)
    (root / "a").mkdir()
    (root / "a" / "shared.csv").write_text("a", encoding="utf-8")
    (root / "a" / "job.sas").write_text(
        'data _null_; infile "shared.csv"; infile "../../escape.csv"; run;\n',
        encoding="utf-8",
    )
    workload = discover_source(root, provider="filesystem", namespace="base07").workloads[0]
    request = InventoryRequest(
        workload,
        root,
        (FixtureRoot("fixture-a", root),),
        (),
        (),
        InventoryPolicy("base07", "1", "synthetic-client"),
        "run-1",
        "attempt-1",
        "2026-09-19T12:00:00+00:00",
    )

    result = evaluate_asset_inventory(request).result
    by_reference = {item["source_reference"]: item for item in result["items"]}

    assert by_reference["shared.csv"]["relative_path"] == "a/shared.csv"
    assert by_reference["shared.csv"]["observation_state"] == "observed"
    assert by_reference["../../escape.csv"]["observation_state"] == "boundary_blocked"
    assert "boundary_escape" in by_reference["../../escape.csv"]["blockers"]


def test_source_mutation_after_discovery_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    request = _request(root, 'data _null_; infile "in.csv"; run;\n')
    (root / "job.sas").write_text('data _null_; infile "xx.csv"; run;\n', encoding="utf-8")

    with pytest.raises(ValueError, match="changed after qualification"):
        evaluate_asset_inventory(request)


def test_unknown_direction_and_duplicate_occurrence_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    request = _request(root, 'data _null_; infile "in.csv"; run;\n')
    analysis = request.workload.data_lineage_analysis
    assert analysis is not None
    bad_access = replace(analysis.accesses[0], role=cast(RelationshipKind, "typo"))
    bad_workload = replace(
        request.workload,
        data_lineage_analysis=replace(analysis, accesses=(bad_access,)),
    )
    with pytest.raises(ValueError, match="Unsupported asset occurrence direction"):
        evaluate_asset_inventory(replace(request, workload=bad_workload))

    duplicate = replace(
        request.workload,
        data_lineage_analysis=replace(analysis, accesses=(analysis.accesses[0],) * 2),
    )
    with pytest.raises(ValueError, match="Duplicate asset occurrence identity"):
        evaluate_asset_inventory(replace(request, workload=duplicate))


def test_empty_workload_cannot_claim_success(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    prepared = evaluate_asset_inventory(_request(root, "data _null_; run;\n"))

    assert prepared.result["items"] == []
    assert "no_eligible_subject" in prepared.result["blockers"]
    assert prepared.result["claims"]["inventory_generated"] is False
    assert asset_inventory_event(prepared.result)["complete"] is False


def test_unsupported_physical_reference_remains_visible(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    prepared = evaluate_asset_inventory(_request(root, "data work.output; set work.input; run;\n"))

    assert prepared.result["items"]
    assert {item["observation_state"] for item in prepared.result["items"]} == {"unsupported"}
    assert all(item["contract_state"] == "unsupported" for item in prepared.result["items"])
    assert "asset_unsupported" in prepared.result["blockers"]
    assert "no_eligible_subject" in prepared.result["blockers"]
    assert prepared.result["claims"]["inventory_generated"] is False


def test_caller_authored_success_assertions_have_no_authority(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    _fixture(root)
    (root / "in.csv").write_text("real bytes", encoding="utf-8")
    request = _request(root, 'data _null_; infile "in.csv"; run;\n')
    dataset = next(item for item in request.workload.datasets if item.kind is DatasetKind.FILE)
    asserted_dataset = replace(
        dataset,
        metadata={
            **dataset.metadata,
            "exists": True,
            "fresh": True,
            "approved": True,
            "authorized": True,
            "complete": True,
        },
    )
    asserted = replace(
        request.workload,
        datasets=tuple(
            asserted_dataset if item.dataset_id == dataset.dataset_id else item
            for item in request.workload.datasets
        ),
    )

    item = evaluate_asset_inventory(replace(request, workload=asserted)).result["items"][0]

    assert item["claims"]["exists"] is True
    assert item["claims"]["fresh"] is False
    assert item["claims"]["authorized"] is False
    assert item["claims"]["complete"] is False
    assert item["authority"] is None
    assert item["delivery_receipt_id"] is None


def test_incomplete_contract_fields_remain_explicit_blockers(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    _fixture(root)
    (root / "feed.csv").write_text("snapshot", encoding="utf-8")
    request = _request(root, 'data _null_; infile "feed.csv"; run;\n')
    dataset = next(item for item in request.workload.datasets if item.kind is DatasetKind.FILE)

    prepared = evaluate_asset_inventory(
        replace(request, contracts=(AssetContract(dataset.dataset_id),))
    )
    item = prepared.result["items"][0]

    assert item["contract_state"] == "pending"
    assert set(item["blockers"]) >= {
        "contract_owner_missing",
        "contract_cadence_missing",
        "contract_timezone_missing",
        "contract_freshness_missing",
    }
    assert asset_inventory_event(prepared.result)["blocked"] is True


def test_freshness_requirement_without_receipt_remains_blocked(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    _fixture(root)
    (root / "feed.csv").write_text("snapshot", encoding="utf-8")
    request = _request(root, 'data _null_; infile "feed.csv"; run;\n')
    dataset = next(item for item in request.workload.datasets if item.kind is DatasetKind.FILE)
    contract = AssetContract(
        dataset.dataset_id,
        owner="fixture-owner",
        cadence="daily",
        timezone="UTC",
        freshness_seconds=3600,
    )

    prepared = evaluate_asset_inventory(replace(request, contracts=(contract,)))
    item = prepared.result["items"][0]

    assert item["observation_state"] == "observed"
    assert item["contract_state"] == "pending"
    assert "delivery_receipt_missing" in item["blockers"]
    assert item["delivery_receipt_id"] is None
    assert item["claims"]["fresh"] is False
    assert asset_inventory_event(prepared.result)["blocked"] is True


@pytest.mark.parametrize(
    ("subject", "field", "value"),
    [
        ("dataset", "location", "other.csv"),
        ("dataset", "name", "other.csv"),
        ("access", "normalized_reference", "other.csv"),
        ("access", "source_path", "other/job.sas"),
    ],
)
def test_occurrence_cannot_be_retargeted_to_different_asset_identity(
    tmp_path: Path, subject: str, field: str, value: str
) -> None:
    root = tmp_path / "fixture"
    _fixture(root)
    (root / "declared.csv").write_text("declared", encoding="utf-8")
    (root / "other.csv").write_text("other", encoding="utf-8")
    request = _request(root, 'data _null_; infile "declared.csv"; run;\n')
    analysis = request.workload.data_lineage_analysis
    assert analysis is not None
    access = analysis.accesses[0]
    dataset = next(
        item for item in request.workload.datasets if item.dataset_id == access.dataset_id
    )

    if subject == "dataset":
        changed_dataset = replace(dataset, **{field: value})
        workload = replace(
            request.workload,
            datasets=tuple(
                changed_dataset if item.dataset_id == dataset.dataset_id else item
                for item in request.workload.datasets
            ),
        )
    else:
        changed_access = replace(access, **{field: value})
        workload = replace(
            request.workload,
            data_lineage_analysis=replace(analysis, accesses=(changed_access,)),
        )

    with pytest.raises(ValueError, match="lineage|identity|occurrence"):
        evaluate_asset_inventory(replace(request, workload=workload))


@pytest.mark.parametrize(
    ("delivered_at", "expected_state", "expected_contract", "expected_blocker", "fresh"),
    [
        (
            "2026-09-17T00:00:00+00:00",
            "stale",
            "blocked",
            "delivery_stale",
            False,
        ),
        (
            "2026-09-19T11:30:00+00:00",
            "observed",
            "satisfied",
            None,
            True,
        ),
    ],
)
def test_signed_receipt_is_bound_and_freshness_is_evidence_backed(
    tmp_path: Path,
    delivered_at: str,
    expected_state: str,
    expected_contract: str,
    expected_blocker: str | None,
    fresh: bool,
) -> None:
    root = tmp_path / "fixture"
    _fixture(root)
    (root / "feed.csv").write_text("snapshot", encoding="utf-8")
    initial = _request(root, 'data _null_; infile "feed.csv"; run;\n')
    access = initial.workload.data_lineage_analysis.accesses[0]  # type: ignore[union-attr]
    dataset = next(
        item for item in initial.workload.datasets if item.dataset_id == access.dataset_id
    )
    private_key = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode()
    asset_sha = __import__("hashlib").sha256(b"snapshot").hexdigest()
    policy = InventoryPolicy(
        "base07",
        "1",
        "synthetic-client",
        ("fixture-delivery-authority",),
        (("key-1", public_key),),
    )
    policy_digest = evaluate_asset_inventory(replace(initial, policy=policy)).result[
        "policy_digest"
    ]
    receipt_values = {
        "client_id": "synthetic-client",
        "workload_id": initial.workload.workload_id,
        "source_closure_digest": initial.workload.data_lineage_analysis.source_closure_digest,  # type: ignore[union-attr]
        "policy_digest": policy_digest,
        "run_id": initial.run_id,
        "attempt_id": initial.attempt_id,
        "access_id": access.access_id,
        "asset_sha256": asset_sha,
        "delivered_at": delivered_at,
        "authority": "fixture-delivery-authority",
        "key_id": "key-1",
    }
    receipt_id = stable_id("DELIVERY", receipt_values)
    unsigned = DeliveryReceipt(receipt_id, **receipt_values, signature="")
    signature = base64.b64encode(
        private_key.sign(delivery_receipt_signing_payload(unsigned))
    ).decode()
    receipt = replace(unsigned, signature=signature)
    request = replace(
        initial,
        contracts=(
            AssetContract(
                dataset.dataset_id,
                owner="fixture-owner",
                cadence="daily",
                timezone="UTC",
                freshness_seconds=3600,
                delivery_receipt_required=True,
            ),
        ),
        receipts=(receipt,),
        policy=policy,
    )

    item = evaluate_asset_inventory(request).result["items"][0]

    assert item["observation_state"] == expected_state
    assert item["contract_state"] == expected_contract
    assert item["claims"]["exists"] is True
    assert item["claims"]["fresh"] is fresh
    assert item["authority"] == "fixture-delivery-authority"
    if expected_blocker is None:
        assert item["blockers"] == []
    else:
        assert expected_blocker in item["blockers"]


def test_receipt_cannot_be_replayed_for_changed_bytes(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    _fixture(root)
    (root / "feed.csv").write_text("changed", encoding="utf-8")
    request = _request(root, 'data _null_; infile "feed.csv"; run;\n')
    access = request.workload.data_lineage_analysis.accesses[0]  # type: ignore[union-attr]
    policy_digest = evaluate_asset_inventory(request).result["policy_digest"]
    fake = DeliveryReceipt(
        "DELIVERY-fake",
        "synthetic-client",
        request.workload.workload_id,
        request.workload.data_lineage_analysis.source_closure_digest,  # type: ignore[union-attr]
        policy_digest,
        request.run_id,
        request.attempt_id,
        access.access_id,
        "0" * 64,
        "2026-09-19T11:00:00+00:00",
        "caller",
        "caller-key",
        "asserted",
    )
    denied = evaluate_asset_inventory(replace(request, receipts=(fake,))).result["items"][0]

    assert denied["observation_state"] == "denied"
    assert denied["contract_state"] == "denied"
    assert "delivery_receipt_invalid" in denied["blockers"]


def test_result_identity_is_attempt_and_workload_bound(tmp_path: Path) -> None:
    first = _request(tmp_path / "one", 'data _null_; infile "in.csv"; run;\n')
    second = replace(first, attempt_id="attempt-2")

    one = evaluate_asset_inventory(first).result
    two = evaluate_asset_inventory(second).result

    assert one["inventory_result_id"] != two["inventory_result_id"]
    assert one["items"][0]["inventory_item_id"] != two["items"][0]["inventory_item_id"]

    other = _request(tmp_path / "other", 'data _null_; infile "in.csv"; run;\n', run_id="run-1")
    isolated = evaluate_asset_inventory(other).result
    assert other.workload.workload_id != first.workload.workload_id
    assert isolated["inventory_result_id"] != one["inventory_result_id"]


def test_symlink_asset_is_boundary_blocked_and_contract_canary_is_rejected(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    asset_root = tmp_path / "assets"
    _fixture(source_root)
    _fixture(asset_root)
    outside = tmp_path / "outside.csv"
    outside.write_text("outside", encoding="utf-8")
    (asset_root / "linked.csv").symlink_to(outside)
    (source_root / "job.sas").write_text(
        'data _null_; infile "linked.csv"; run;\n', encoding="utf-8"
    )
    workload = discover_source(source_root, provider="filesystem", namespace="base07").workloads[0]
    request = InventoryRequest(
        workload,
        source_root,
        (FixtureRoot("fixture-a", asset_root),),
        (),
        (),
        InventoryPolicy("base07", "1", "synthetic-client"),
        "run-1",
        "attempt-1",
        "2026-09-19T12:00:00+00:00",
    )

    item = evaluate_asset_inventory(request).result["items"][0]
    assert item["observation_state"] == "boundary_blocked"
    assert item["asset_sha256"] is None

    dataset_id = item["dataset_id"]
    unsafe = replace(
        request,
        contracts=(AssetContract(dataset_id, owner="secret_canary_do_not_persist"),),
    )
    with pytest.raises(ValueError, match="Unsafe asset contract owner"):
        evaluate_asset_inventory(unsafe)


def test_immutable_publication_recovers_missing_projection_without_rewriting_result(
    tmp_path: Path,
) -> None:
    prepared = evaluate_asset_inventory(
        _request(tmp_path / "fixture", 'data _null_; infile "missing.csv"; run;\n')
    )
    output = tmp_path / "output"
    result_path = output / "asset-inventory" / (prepared.result["inventory_result_id"] + ".json")
    from smf.immutable_files import publish_json

    publish_json(result_path, prepared.result, "asset inventory result", root=output)
    before = result_path.read_bytes()

    published_result, projection_path = publish_asset_inventory(prepared, output)

    assert published_result.read_bytes() == before
    assert (
        json.loads(projection_path.read_text())["inventory_result_id"]
        == prepared.result["inventory_result_id"]
    )
    assert publish_asset_inventory(prepared, output) == (published_result, projection_path)


def test_publication_recovers_projection_from_canonical_result_after_reevaluation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "fixture"
    request = _request(root, 'data _null_; infile "feed.csv"; run;\n')
    (root / "feed.csv").write_text("first", encoding="utf-8")
    original = evaluate_asset_inventory(request)
    original_digest = original.result["content_digest"]
    output = tmp_path / "output"
    result_path, projection_path = publish_asset_inventory(original, output)
    canonical_bytes = result_path.read_bytes()
    projection_path.unlink()
    del original

    (root / "feed.csv").write_text("second", encoding="utf-8")
    reevaluated = evaluate_asset_inventory(
        replace(request, evaluated_at="2026-09-19T13:00:00+00:00")
    )
    assert reevaluated.result["content_digest"] != original_digest

    recovered_result, recovered_projection = publish_asset_inventory(reevaluated, output)

    assert recovered_result.read_bytes() == canonical_bytes
    projection = json.loads(recovered_projection.read_text())
    assert projection["content_digest"] == original_digest
    assert projection["content_digest"] != reevaluated.result["content_digest"]


def test_fixture_root_must_be_marked_and_temporary(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    root.mkdir()
    (root / "job.sas").write_text('data _null_; infile "in.csv"; run;\n')
    workload = discover_source(root, provider="filesystem", namespace="base07").workloads[0]
    request = InventoryRequest(
        workload,
        root,
        (FixtureRoot("fixture-a", root),),
        (),
        (),
        InventoryPolicy("base07", "1", "synthetic-client"),
        "run-1",
        "attempt-1",
        "2026-09-19T12:00:00+00:00",
    )

    with pytest.raises(ValueError, match="marker"):
        evaluate_asset_inventory(request)
