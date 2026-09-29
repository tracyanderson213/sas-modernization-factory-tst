"""DP-05 deterministic, stable, sample-only row and cell comparison."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from decimal import Decimal
from importlib.resources import files
from pathlib import Path
from typing import Any, ClassVar, Literal, cast

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from smf.immutable_files import publish_json, read_published_json
from smf.security.ai_admission import contains_protected_data
from smf.upstream.crypto import sign_payload, verify_proof
from smf.workload.sanitization import sanitize_discovery_value

DuplicatePolicy = Literal["reject", "stable_ordinal"]
ObservationState = Literal["observed", "unavailable", "biased_selection", "duplicate_keys"]
AuthorityState = Literal["source", "target"]
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _safe_id(value: str, label: str) -> None:
    lowered = value.casefold()
    if (
        not _SAFE_ID.fullmatch(value)
        or value in {".", ".."}
        or any(marker in lowered for marker in ("bearer", "secret", "password", "token"))
        or contains_protected_data(value)
        or sanitize_discovery_value(value) != value
    ):
        raise ValueError(f"Unsafe DP-05 {label}")


def _validate(schema_name: str, payload: dict[str, Any]) -> None:
    schemas = {
        name: json.loads(files("smf.schemas").joinpath(name).read_text("utf-8"))
        for name in ("dp05-sample-observation.schema.json", "dp05-sample-result.schema.json")
    }
    registry = Registry()
    for schema in schemas.values():
        registry = registry.with_resource(cast(str, schema["$id"]), Resource.from_contents(schema))
    errors = sorted(
        Draft202012Validator(schemas[schema_name], registry=registry).iter_errors(payload),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValueError(f"DP-05 schema validation failed: {detail}")


def _canonical_scalar(value: object) -> dict[str, str]:
    if value is None:
        return {"type": "null", "value": ""}
    if isinstance(value, bool):
        return {"type": "boolean", "value": "true" if value else "false"}
    if isinstance(value, int):
        return {"type": "integer", "value": str(value)}
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("DP-05 sample value must be finite")
        return {"type": "float", "value": repr(value)}
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("DP-05 sample value must be finite")
        return {"type": "decimal", "value": "0" if value == 0 else format(value.normalize(), "f")}
    if isinstance(value, str):
        return {"type": "string", "value": value}
    raise ValueError("DP-05 sample value type is unsupported")


def _safe_scalar(value: object) -> dict[str, str]:
    canonical = _canonical_scalar(value)
    text = canonical["value"]
    if contains_protected_data(text) or sanitize_discovery_value(text) != text:
        raise ValueError("DP-05 sample contains protected data")
    return canonical


@dataclass(frozen=True)
class DP05TrustPolicy:
    policy_id: str
    policy_version: str
    verification_keys: tuple[tuple[str, str], ...]
    source_key_ids: tuple[str, ...]
    target_key_ids: tuple[str, ...]
    source_authorities: tuple[tuple[str, str], ...]
    target_authorities: tuple[tuple[str, str], ...]
    protected_value_key: bytes

    def public_payload(self) -> dict[str, Any]:
        keys = dict(self.verification_keys)
        source_authorities, target_authorities = (
            dict(self.source_authorities),
            dict(self.target_authorities),
        )
        source_keys, target_keys = set(self.source_key_ids), set(self.target_key_ids)
        for value in (
            self.policy_id,
            self.policy_version,
            *keys,
            *source_authorities,
            *target_authorities,
        ):
            _safe_id(value, "trust identity")
        if (
            len(keys) != len(self.verification_keys)
            or not source_keys
            or not target_keys
            or source_keys & target_keys
            or not (source_keys | target_keys).issubset(keys)
            or not source_authorities
            or not target_authorities
            or set(source_authorities) & set(target_authorities)
            or set(source_authorities.values()) & set(target_authorities.values())
        ):
            raise ValueError("DP-05 trust domains must be unique, complete, and disjoint")
        try:
            key_material = [base64.b64decode(value, validate=True) for value in keys.values()]
        except (ValueError, binascii.Error) as exc:
            raise ValueError("DP-05 verification key is not canonical base64") from exc
        if any(len(value) != 32 for value in key_material) or len(set(key_material)) != len(
            key_material
        ):
            raise ValueError("DP-05 trust domains cannot alias Ed25519 key material")
        for digest in (*source_authorities.values(), *target_authorities.values()):
            if not _DIGEST.fullmatch(digest):
                raise ValueError("DP-05 authority digest is invalid")
        if len(self.protected_value_key) < 32:
            raise ValueError("DP-05 protected-value key must be at least 32 bytes")
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "verification_keys": {key: keys[key] for key in sorted(keys)},
            "source_key_ids": sorted(source_keys),
            "target_key_ids": sorted(target_keys),
            "source_authorities": {
                key: source_authorities[key] for key in sorted(source_authorities)
            },
            "target_authorities": {
                key: target_authorities[key] for key in sorted(target_authorities)
            },
            "protected_value_key_digest": _digest(self.protected_value_key.hex()),
        }

    @property
    def digest(self) -> str:
        return _digest(self.public_payload())


@dataclass(frozen=True)
class SampleDatasetBinding:
    dataset_id: str
    snapshot_id: str
    snapshot_digest: str
    scope_id: str
    scope_digest: str

    def to_dict(self) -> dict[str, str]:
        payload = asdict(self)
        for name in ("dataset_id", "snapshot_id", "scope_id"):
            _safe_id(payload[name], name)
        for name in ("snapshot_digest", "scope_digest"):
            if not _DIGEST.fullmatch(payload[name]):
                raise ValueError(f"Invalid DP-05 {name}")
        return payload


@dataclass(frozen=True)
class SamplePolicy:
    policy_id: str
    policy_version: str
    key_columns: tuple[str, ...]
    compare_columns: tuple[str, ...]
    sample_size: int
    seed: str
    duplicate_policy: DuplicatePolicy
    sensitive_columns: tuple[str, ...] = ()
    maximum_duplicate_rows_per_key: int = 1000
    selection_algorithm: Literal["sha256-key-ordinal-v1"] = "sha256-key-ordinal-v1"
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        for name in (
            self.policy_id,
            self.policy_version,
            self.seed,
            *self.key_columns,
            *self.compare_columns,
        ):
            _safe_id(name, "policy identity")
        if not self.key_columns or len(set(self.key_columns)) != len(self.key_columns):
            raise ValueError("DP-05 key columns must be non-empty and unique")
        if not self.compare_columns or len(set(self.compare_columns)) != len(self.compare_columns):
            raise ValueError("DP-05 comparison columns must be non-empty and unique")
        if set(self.key_columns) & set(self.compare_columns):
            raise ValueError("DP-05 key and comparison columns must be distinct")
        governed = set(self.key_columns) | set(self.compare_columns)
        if len(set(self.sensitive_columns)) != len(self.sensitive_columns) or not set(
            self.sensitive_columns
        ).issubset(governed):
            raise ValueError("DP-05 sensitive columns must be unique governed columns")
        sensitive_names = re.compile(r"(?i)(?:member|patient|mrn|ssn|social.security)")
        if any(sensitive_names.search(name) for name in governed - set(self.sensitive_columns)):
            raise ValueError("DP-05 sensitive column requires governed classification")
        if (
            not isinstance(self.sample_size, int)
            or isinstance(self.sample_size, bool)
            or not 1 <= self.sample_size <= 100_000
        ):
            raise ValueError("DP-05 sample_size must be between 1 and 100000")
        if (
            not isinstance(self.maximum_duplicate_rows_per_key, int)
            or isinstance(self.maximum_duplicate_rows_per_key, bool)
            or not 1 <= self.maximum_duplicate_rows_per_key <= 10_000
        ):
            raise ValueError("DP-05 duplicate bound must be between 1 and 10000")
        return {
            **asdict(self),
            "key_columns": list(self.key_columns),
            "compare_columns": list(self.compare_columns),
            "sensitive_columns": list(self.sensitive_columns),
        }


@dataclass(frozen=True)
class SampleRow:
    sample_id: str
    key_digest: str
    duplicate_ordinal: int
    selection_score: str
    cell_digests: tuple[tuple[str, str], ...]

    def to_dict(self) -> dict[str, Any]:
        if not _DIGEST.fullmatch(self.sample_id) or not _DIGEST.fullmatch(self.key_digest):
            raise ValueError("Invalid DP-05 sample identity")
        if not _DIGEST.fullmatch(self.selection_score):
            raise ValueError("Invalid DP-05 selection score")
        if self.duplicate_ordinal < 0:
            raise ValueError("Invalid DP-05 duplicate ordinal")
        cells = dict(self.cell_digests)
        if len(cells) != len(self.cell_digests):
            raise ValueError("Duplicate DP-05 cell column")
        for name, digest in cells.items():
            _safe_id(name, "cell column")
            if not _DIGEST.fullmatch(digest):
                raise ValueError("Invalid DP-05 cell digest")
        return {
            "sample_id": self.sample_id,
            "key_digest": self.key_digest,
            "duplicate_ordinal": self.duplicate_ordinal,
            "selection_score": self.selection_score,
            "cell_digests": cells,
        }


@dataclass(frozen=True)
class SampleObservation:
    binding: SampleDatasetBinding
    adapter_id: str
    adapter_version: str
    state: ObservationState
    reason: str
    population_count: int
    unique_key_count: int
    duplicate_key_count: int
    rows: tuple[SampleRow, ...]
    execution_id: str = "sha256:" + "0" * 64
    authority_id: str | None = None
    authority_digest: str | None = None
    proof: dict[str, str] | None = None

    def projection_without_execution(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "state": self.state,
            "reason": self.reason,
            "population_count": self.population_count,
            "unique_key_count": self.unique_key_count,
            "duplicate_key_count": self.duplicate_key_count,
            "rows": [row.to_dict() for row in self.rows],
            "authority_id": self.authority_id,
            "authority_digest": self.authority_digest,
        }

    def projection(self) -> dict[str, Any]:
        return {
            **self.projection_without_execution(),
            "execution_id": self.execution_id,
            "proof": self.proof,
        }

    def to_dict(self) -> dict[str, Any]:
        _safe_id(self.adapter_id, "adapter_id")
        _safe_id(self.adapter_version, "adapter_version")
        for value in (self.population_count, self.unique_key_count, self.duplicate_key_count):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError("DP-05 observation counts must be non-negative integers")
        payload = self.projection()
        payload["content_digest"] = _digest(
            {**self.projection_without_execution(), "execution_id": self.execution_id}
        )
        _validate("dp05-sample-observation.schema.json", payload)
        return payload


def _protected_scalar(value: object, key: bytes) -> dict[str, str]:
    canonical = _canonical_scalar(value)
    token = hmac.new(key, _canonical(canonical), hashlib.sha256).hexdigest()
    return {"type": "protected-hmac-sha256", "value": token}


def _key_and_row(
    row: Mapping[str, object], policy: SamplePolicy, protected_value_key: bytes
) -> tuple[str, str, dict[str, str]]:
    missing = (set(policy.key_columns) | set(policy.compare_columns)) - set(row)
    if missing:
        raise ValueError("DP-05 row is missing a governed column")
    sensitive = set(policy.sensitive_columns)

    def scalar(name: str) -> dict[str, str]:
        if name in sensitive:
            return _protected_scalar(row[name], protected_value_key)
        return _safe_scalar(row[name])

    key_digest = _digest([scalar(name) for name in policy.key_columns])
    cells = {name: _digest(scalar(name)) for name in policy.compare_columns}
    row_digest = _digest(cells)
    return key_digest, row_digest, cells


def _sample_id(key_digest: str, ordinal: int) -> str:
    return _digest({"key_digest": key_digest, "duplicate_ordinal": ordinal})


def _selection_score(seed: str, sample_id: str) -> str:
    return _digest({"algorithm": "sha256-key-ordinal-v1", "seed": seed, "sample_id": sample_id})


def verify_sample_observation(
    observation: SampleObservation,
    policy: SamplePolicy,
    trust_policy: DP05TrustPolicy,
    *,
    side: AuthorityState,
    request_digest: str,
) -> None:
    payload = observation.to_dict()
    if (
        observation.adapter_id != StableSampleAdapter.adapter_id
        or observation.adapter_version != StableSampleAdapter.adapter_version
    ):
        raise ValueError("DP-05 observation adapter is not qualified")
    if len(observation.rows) > policy.sample_size:
        raise ValueError("DP-05 observation exceeds sample bound")
    if (
        len(observation.rows) > observation.population_count
        or observation.unique_key_count > observation.population_count
        or observation.duplicate_key_count > observation.unique_key_count
    ):
        raise ValueError("DP-05 observation coverage is inconsistent")
    if observation.state == "observed":
        if observation.reason != "observed" or len(observation.rows) != min(
            policy.sample_size, observation.population_count
        ):
            raise ValueError("DP-05 observed sample coverage is incomplete")
        if policy.duplicate_policy == "reject" and observation.duplicate_key_count:
            raise ValueError("DP-05 rejected duplicates cannot appear in an observed sample")
    elif observation.rows:
        raise ValueError("DP-05 non-observed sample cannot carry selected rows")
    if observation.state == "duplicate_keys" and (
        observation.duplicate_key_count == 0
        or observation.reason not in {"duplicate_keys_rejected", "duplicate_limit_exceeded"}
    ):
        raise ValueError("DP-05 duplicate failure evidence is inconsistent")
    if (
        observation.state == "biased_selection"
        and observation.reason != "input_not_canonical_order"
    ):
        raise ValueError("DP-05 biased selection evidence is inconsistent")
    expected_order = sorted(observation.rows, key=lambda row: (row.selection_score, row.sample_id))
    if list(observation.rows) != expected_order:
        raise ValueError("DP-05 sample selection is biased or unordered")
    if len({row.sample_id for row in observation.rows}) != len(observation.rows):
        raise ValueError("DP-05 sample contains duplicate identities")
    for row in observation.rows:
        if row.sample_id != _sample_id(row.key_digest, row.duplicate_ordinal):
            raise ValueError("DP-05 sample identity mismatch")
        if row.selection_score != _selection_score(policy.seed, row.sample_id):
            raise ValueError("DP-05 sample selection is biased or mutated")
        if set(name for name, _ in row.cell_digests) != set(policy.compare_columns):
            raise ValueError("DP-05 sample cells do not match policy")
    if payload["content_digest"] != _digest(
        {**observation.projection_without_execution(), "execution_id": observation.execution_id}
    ):
        raise ValueError("DP-05 observation digest mismatch")
    if observation.reason in {"authority_missing", "authority_untrusted", "prerequisite_blocked"}:
        if (
            observation.authority_id is not None
            or observation.proof is not None
            or observation.rows
        ):
            raise ValueError("DP-05 authority blocker carries unauthorized evidence")
        return
    authorities = dict(
        trust_policy.source_authorities if side == "source" else trust_policy.target_authorities
    )
    allowed_keys = set(
        trust_policy.source_key_ids if side == "source" else trust_policy.target_key_ids
    )
    if (
        observation.authority_id not in authorities
        or authorities[observation.authority_id] != observation.authority_digest
    ):
        raise ValueError("DP-05 observation authority is untrusted")
    expected_execution = _digest(
        {
            "observation": observation.projection_without_execution(),
            "request_digest": request_digest,
            "policy_digest": _digest(policy.to_dict()),
            "side": side,
        }
    )
    if observation.execution_id != expected_execution:
        raise ValueError("DP-05 execution observation is not request-bound")
    verify_proof(
        payload,
        trusted_keys=dict(trust_policy.verification_keys),
        allowed_key_ids=allowed_keys,
    )


@dataclass(frozen=True)
class StableSampleAdapter:
    """Select a bounded sample from a canonical key/row-digest ordered stream."""

    row_factory: Callable[[], Iterable[Mapping[str, object]]]
    signing_key_path: Path | None = None
    signing_key_id: str | None = None
    authority_id: str | None = None
    authority_digest: str | None = None
    adapter_id: ClassVar[str] = "stable-row-stream"
    adapter_version: ClassVar[str] = "1.0.0"

    def observe(
        self,
        binding: SampleDatasetBinding,
        policy: SamplePolicy,
        trust_policy: DP05TrustPolicy,
        *,
        side: AuthorityState,
        request_digest: str,
    ) -> SampleObservation:
        authorities = dict(
            trust_policy.source_authorities if side == "source" else trust_policy.target_authorities
        )
        allowed_keys = set(
            trust_policy.source_key_ids if side == "source" else trust_policy.target_key_ids
        )
        if (
            self.signing_key_path is None
            or self.signing_key_id is None
            or self.authority_id is None
        ):
            return SampleObservation(
                binding,
                self.adapter_id,
                self.adapter_version,
                "unavailable",
                "authority_missing",
                0,
                0,
                0,
                (),
            )
        if (
            self.signing_key_id not in allowed_keys
            or self.authority_id not in authorities
            or authorities[self.authority_id] != self.authority_digest
        ):
            return SampleObservation(
                binding,
                self.adapter_id,
                self.adapter_version,
                "unavailable",
                "authority_untrusted",
                0,
                0,
                0,
                (),
            )
        observation = self._observe_unsigned(binding, policy, trust_policy.protected_value_key)
        candidate = replace(
            observation, authority_id=self.authority_id, authority_digest=self.authority_digest
        )
        execution_id = _digest(
            {
                "observation": candidate.projection_without_execution(),
                "request_digest": request_digest,
                "policy_digest": _digest(policy.to_dict()),
                "side": side,
            }
        )
        candidate = replace(candidate, execution_id=execution_id)
        payload = candidate.to_dict()
        sign_payload(payload, private_key_path=self.signing_key_path, key_id=self.signing_key_id)
        return replace(candidate, proof=payload["proof"])

    def _observe_unsigned(
        self, binding: SampleDatasetBinding, policy: SamplePolicy, protected_value_key: bytes
    ) -> SampleObservation:
        selected: list[SampleRow] = []
        population_count = 0
        unique_key_count = 0
        duplicate_key_count = 0
        prior_order: tuple[str, str] | None = None
        current_key: str | None = None
        current_rows: list[tuple[str, dict[str, str]]] = []

        def admit_group() -> ObservationState | None:
            nonlocal unique_key_count, duplicate_key_count
            if current_key is None:
                return None
            unique_key_count += 1
            if len(current_rows) > 1:
                duplicate_key_count += 1
                if policy.duplicate_policy == "reject":
                    return "duplicate_keys"
            if len(current_rows) > policy.maximum_duplicate_rows_per_key:
                return "duplicate_keys"
            for ordinal, (_, cells) in enumerate(current_rows):
                identity = _sample_id(current_key, ordinal)
                selected.append(
                    SampleRow(
                        identity,
                        current_key,
                        ordinal,
                        _selection_score(policy.seed, identity),
                        tuple((name, cells[name]) for name in policy.compare_columns),
                    )
                )
            selected.sort(key=lambda item: (item.selection_score, item.sample_id))
            del selected[policy.sample_size :]
            return None

        try:
            for raw in self.row_factory():
                key_digest, row_digest, cells = _key_and_row(raw, policy, protected_value_key)
                order = (key_digest, row_digest)
                if prior_order is not None and order < prior_order:
                    return SampleObservation(
                        binding,
                        self.adapter_id,
                        self.adapter_version,
                        "biased_selection",
                        "input_not_canonical_order",
                        population_count,
                        unique_key_count,
                        duplicate_key_count,
                        (),
                    )
                prior_order = order
                population_count += 1
                if current_key is not None and key_digest != current_key:
                    state = admit_group()
                    if state is not None:
                        return SampleObservation(
                            binding,
                            self.adapter_id,
                            self.adapter_version,
                            state,
                            "duplicate_keys_rejected",
                            population_count,
                            unique_key_count,
                            duplicate_key_count,
                            (),
                        )
                    current_rows = []
                current_key = key_digest
                current_rows.append((row_digest, cells))
                if len(current_rows) > policy.maximum_duplicate_rows_per_key:
                    return SampleObservation(
                        binding,
                        self.adapter_id,
                        self.adapter_version,
                        "duplicate_keys",
                        "duplicate_limit_exceeded",
                        population_count,
                        unique_key_count + 1,
                        duplicate_key_count + 1,
                        (),
                    )
            state = admit_group()
            if state is not None:
                return SampleObservation(
                    binding,
                    self.adapter_id,
                    self.adapter_version,
                    state,
                    "duplicate_keys_rejected",
                    population_count,
                    unique_key_count,
                    duplicate_key_count,
                    (),
                )
            if population_count == 0:
                return SampleObservation(
                    binding,
                    self.adapter_id,
                    self.adapter_version,
                    "unavailable",
                    "empty_population",
                    0,
                    0,
                    0,
                    (),
                )
            observation = SampleObservation(
                binding,
                self.adapter_id,
                self.adapter_version,
                "observed",
                "observed",
                population_count,
                unique_key_count,
                duplicate_key_count,
                tuple(selected),
            )
            return observation
        except Exception:
            return SampleObservation(
                binding,
                self.adapter_id,
                self.adapter_version,
                "unavailable",
                "provider_error",
                0,
                0,
                0,
                (),
            )


@dataclass(frozen=True)
class DP05Request:
    client_id: str
    workload_id: str
    run_id: str
    attempt_id: str
    evaluated_at: str
    source: SampleDatasetBinding
    target: SampleDatasetBinding
    trust_policy_digest: str
    source_adapter_id: str = StableSampleAdapter.adapter_id
    source_adapter_version: str = StableSampleAdapter.adapter_version
    target_adapter_id: str = StableSampleAdapter.adapter_id
    target_adapter_version: str = StableSampleAdapter.adapter_version

    def to_dict(self) -> dict[str, Any]:
        for name in (
            "client_id",
            "workload_id",
            "run_id",
            "attempt_id",
            "source_adapter_id",
            "source_adapter_version",
            "target_adapter_id",
            "target_adapter_version",
        ):
            _safe_id(cast(str, getattr(self, name)), name)
        if not _RFC3339.fullmatch(self.evaluated_at):
            raise ValueError("DP-05 evaluated_at must be canonical UTC RFC3339")
        datetime.fromisoformat(self.evaluated_at.removesuffix("Z") + "+00:00")
        if not _DIGEST.fullmatch(self.trust_policy_digest):
            raise ValueError("Invalid DP-05 trust policy digest")
        if any(
            value != expected
            for value, expected in (
                (self.source_adapter_id, StableSampleAdapter.adapter_id),
                (self.source_adapter_version, StableSampleAdapter.adapter_version),
                (self.target_adapter_id, StableSampleAdapter.adapter_id),
                (self.target_adapter_version, StableSampleAdapter.adapter_version),
            )
        ):
            raise ValueError("DP-05 request adapter is not qualified")
        return {**asdict(self), "source": self.source.to_dict(), "target": self.target.to_dict()}


def _projection(
    request: DP05Request,
    policy: SamplePolicy,
    source: SampleObservation,
    target: SampleObservation,
    trust_policy: DP05TrustPolicy,
) -> dict[str, Any]:
    request_payload, policy_payload = request.to_dict(), policy.to_dict()
    if request.trust_policy_digest != trust_policy.digest:
        raise ValueError("DP-05 request does not bind the active trust policy")
    request_digest = _digest(request_payload)
    verify_sample_observation(
        source, policy, trust_policy, side="source", request_digest=request_digest
    )
    verify_sample_observation(
        target, policy, trust_policy, side="target", request_digest=request_digest
    )
    if source.binding != request.source or target.binding != request.target:
        raise ValueError("DP-05 observations are not request-bound")
    blockers: list[str] = []
    failures: list[str] = []
    scope_blocked = (
        request.source.scope_id != request.target.scope_id
        or request.source.scope_digest != request.target.scope_digest
    )
    if scope_blocked:
        blockers.append("snapshot_scope_mismatch")
    for side, observation in (("source", source), ("target", target)):
        if observation.state == "unavailable" and not scope_blocked:
            blockers.append(f"{side}_{observation.reason}")
        elif observation.state == "biased_selection":
            failures.append(f"{side}_biased_selection")
        elif observation.state == "duplicate_keys":
            failures.append(f"{side}_duplicate_keys")
    if source.population_count != target.population_count:
        failures.append("population_count_mismatch")
    source_rows = {row.sample_id: row for row in source.rows}
    target_rows = {row.sample_id: row for row in target.rows}
    alignments: list[dict[str, Any]] = []
    cell_mismatch_count = 0
    unmatched_count = 0
    for sample_id in sorted(set(source_rows) | set(target_rows)):
        left, right = source_rows.get(sample_id), target_rows.get(sample_id)
        if left is None or right is None:
            status = "unmatched"
            unmatched_count += 1
            mismatches: list[str] = []
        else:
            left_cells, right_cells = dict(left.cell_digests), dict(right.cell_digests)
            mismatches = [
                name for name in policy.compare_columns if left_cells[name] != right_cells[name]
            ]
            cell_mismatch_count += len(mismatches)
            status = "matched" if not mismatches else "cell_mismatch"
        alignments.append(
            {"sample_id": sample_id, "status": status, "mismatched_columns": mismatches}
        )
    if unmatched_count:
        failures.append("unmatched_sample_rows")
    if cell_mismatch_count:
        failures.append("sampled_cell_mismatch")
    if (source.state == "observed" and not source.rows) or (
        target.state == "observed" and not target.rows
    ):
        blockers.append("no_sample_rows")
    status = "blocked" if blockers else "failed" if failures else "passed"
    return {
        "schema_version": "1.0",
        "assurance_scope": "sample_only",
        "request": request_payload,
        "request_digest": _digest(request_payload),
        "policy": policy_payload,
        "policy_digest": _digest(policy_payload),
        "trust_policy": trust_policy.public_payload(),
        "trust_policy_digest": trust_policy.digest,
        "source_observation": source.to_dict(),
        "target_observation": target.to_dict(),
        "status": status,
        "terminal_disposition": "blocked"
        if status == "blocked"
        else "sample_match"
        if status == "passed"
        else "sample_mismatch",
        "blockers": sorted(set(blockers)),
        "failures": sorted(set(failures)),
        "coverage": {
            "source_population_count": source.population_count,
            "target_population_count": target.population_count,
            "source_selected_count": len(source.rows),
            "target_selected_count": len(target.rows),
            "aligned_count": sum(item["status"] == "matched" for item in alignments),
            "unmatched_count": unmatched_count,
            "cell_mismatch_count": cell_mismatch_count,
        },
        "alignments": alignments,
        "claims": {
            "generated": False,
            "executed": False,
            "sample_validation_executed": source.state == target.state == "observed",
            "validated": status in {"passed", "failed"},
            "sample_check_passed": status == "passed",
            "sample_only_assurance": status == "passed",
            "full_dataset_parity_passed": False,
            "cell_parity_passed": False,
            "data_parity_passed": False,
            "human_assisted": False,
            "blocked": status == "blocked",
            "certified": False,
            "humana_validated": False,
        },
    }


def compare_deterministic_samples(
    request: DP05Request,
    policy: SamplePolicy,
    *,
    source_adapter: StableSampleAdapter,
    target_adapter: StableSampleAdapter,
    trust_policy: DP05TrustPolicy,
) -> dict[str, Any]:
    request.to_dict()
    policy.to_dict()
    request_digest = _digest(request.to_dict())
    if (
        type(source_adapter) is not StableSampleAdapter
        or type(target_adapter) is not StableSampleAdapter
    ):
        raise TypeError("DP-05 adapters must be the exact qualified implementation")
    if (
        request.source.scope_id != request.target.scope_id
        or request.source.scope_digest != request.target.scope_digest
    ):
        source = SampleObservation(
            request.source,
            source_adapter.adapter_id,
            source_adapter.adapter_version,
            "unavailable",
            "prerequisite_blocked",
            0,
            0,
            0,
            (),
        )
        target = SampleObservation(
            request.target,
            target_adapter.adapter_id,
            target_adapter.adapter_version,
            "unavailable",
            "prerequisite_blocked",
            0,
            0,
            0,
            (),
        )
    else:
        source = source_adapter.observe(
            request.source,
            policy,
            trust_policy,
            side="source",
            request_digest=request_digest,
        )
        target = target_adapter.observe(
            request.target,
            policy,
            trust_policy,
            side="target",
            request_digest=request_digest,
        )
    projection = _projection(request, policy, source, target, trust_policy)
    result = {"result_id": _digest(projection), **projection}
    result["content_digest"] = _digest(result)
    verify_dp05_result(result, trust_policy=trust_policy)
    return result


def _observation(payload: dict[str, Any]) -> SampleObservation:
    rows = tuple(
        SampleRow(
            item["sample_id"],
            item["key_digest"],
            item["duplicate_ordinal"],
            item["selection_score"],
            tuple(cast(dict[str, str], item["cell_digests"]).items()),
        )
        for item in cast(list[dict[str, Any]], payload["rows"])
    )
    return SampleObservation(
        SampleDatasetBinding(**cast(dict[str, str], payload["binding"])),
        payload["adapter_id"],
        payload["adapter_version"],
        payload["state"],
        payload["reason"],
        payload["population_count"],
        payload["unique_key_count"],
        payload["duplicate_key_count"],
        rows,
        payload["execution_id"],
        payload["authority_id"],
        payload["authority_digest"],
        payload["proof"],
    )


def verify_dp05_result(result: dict[str, Any], *, trust_policy: DP05TrustPolicy) -> None:
    _validate("dp05-sample-result.schema.json", result)
    content = dict(result)
    observed_digest = content.pop("content_digest")
    if observed_digest != _digest(content):
        raise ValueError("DP-05 content digest mismatch")
    projection = dict(content)
    observed_id = projection.pop("result_id")
    if observed_id != _digest(projection):
        raise ValueError("DP-05 result identity mismatch")
    raw_request = cast(dict[str, Any], result["request"])
    request = DP05Request(
        raw_request["client_id"],
        raw_request["workload_id"],
        raw_request["run_id"],
        raw_request["attempt_id"],
        raw_request["evaluated_at"],
        SampleDatasetBinding(**raw_request["source"]),
        SampleDatasetBinding(**raw_request["target"]),
        raw_request["trust_policy_digest"],
        raw_request["source_adapter_id"],
        raw_request["source_adapter_version"],
        raw_request["target_adapter_id"],
        raw_request["target_adapter_version"],
    )
    raw_policy = cast(dict[str, Any], result["policy"])
    policy = SamplePolicy(
        policy_id=raw_policy["policy_id"],
        policy_version=raw_policy["policy_version"],
        key_columns=tuple(raw_policy["key_columns"]),
        compare_columns=tuple(raw_policy["compare_columns"]),
        sample_size=raw_policy["sample_size"],
        seed=raw_policy["seed"],
        duplicate_policy=raw_policy["duplicate_policy"],
        sensitive_columns=tuple(raw_policy["sensitive_columns"]),
        maximum_duplicate_rows_per_key=raw_policy["maximum_duplicate_rows_per_key"],
        selection_algorithm=raw_policy["selection_algorithm"],
        schema_version=raw_policy["schema_version"],
    )
    if result["trust_policy"] != trust_policy.public_payload():
        raise ValueError("DP-05 result trust policy differs from active authority")
    expected_projection = _projection(
        request,
        policy,
        _observation(cast(dict[str, Any], result["source_observation"])),
        _observation(cast(dict[str, Any], result["target_observation"])),
        trust_policy,
    )
    expected = {"result_id": _digest(expected_projection), **expected_projection}
    expected["content_digest"] = _digest(expected)
    if result != expected:
        raise ValueError("DP-05 result does not match governed samples and policy")


def result_path(root: Path, request: DP05Request) -> Path:
    request.to_dict()
    return (
        root
        / request.client_id
        / request.workload_id
        / request.run_id
        / request.attempt_id
        / "dp05"
        / "result.json"
    )


def publish_dp05_result(
    root: Path,
    request: DP05Request,
    policy: SamplePolicy,
    *,
    source_adapter: StableSampleAdapter,
    target_adapter: StableSampleAdapter,
    trust_policy: DP05TrustPolicy,
) -> Path:
    result = compare_deterministic_samples(
        request,
        policy,
        source_adapter=source_adapter,
        target_adapter=target_adapter,
        trust_policy=trust_policy,
    )
    path = result_path(root, request)
    publish_json(path, result, "DP-05 sample result", root=root)
    observed = read_published_json(path, root=root, label="DP-05 sample result")
    if not isinstance(observed, dict):
        raise ValueError("Published DP-05 result must be an object")
    verify_dp05_result(observed, trust_policy=trust_policy)
    if observed != result:
        raise ValueError("Published DP-05 result differs from candidate")
    return path
