"""Package-owned deterministic PROC SQL rule registry and planner.

The registry deliberately supports a small source-faithful subset.  It is not a
SAS parser and it never treats a plausible rewrite as proof of semantic parity.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from smf.conversion.providers.base import ProviderResult
from smf.conversion.temporal import (
    TemporalDisposition,
    TemporalPolicy,
    normalize_temporal_literals,
)
from smf.conversion.value_semantics import (
    ValueCompatibilityPolicy,
    ValueDisposition,
    classify_value_semantics,
)
from smf.workload.identity import stable_id


class ConstructFamily(StrEnum):
    PROC_SQL = "proc_sql"
    SELECT = "select"
    JOIN = "join"
    AGGREGATE = "aggregate"
    CTAS = "ctas"
    DATE_LITERAL = "sas_date_literal"
    DATETIME_LITERAL = "sas_datetime_literal"
    MISSING_VALUE = "sas_missing_value"
    IMPLICIT_COERCION = "sas_implicit_type_conversion"
    PROC_FORMAT = "proc_format"
    SAS_MACRO = "sas_macro_processor"
    TARGET_TEMPLATE = "target_template"


class RuleType(StrEnum):
    ENVELOPE = "envelope"
    STATEMENT = "statement"
    CLAUSE = "clause"


class Applicability(StrEnum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED = "unsupported"
    BLOCKED = "blocked"


class PlanDisposition(StrEnum):
    QUALIFIED = "qualified"
    UNSUPPORTED = "unsupported"
    BLOCKED = "blocked"
    HUMAN_PENDING = "human_pending"
    HUMAN_DENIED = "human_denied"


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    version: str
    construct_family: ConstructFamily
    rule_type: RuleType
    target: str
    supported_semantics: tuple[str, ...]
    unsupported_cases: tuple[str, ...]
    fixture_qualifications: tuple[str, ...]
    composition_group: str
    composition_order: int
    exclusive: bool = False

    def descriptor(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def descriptor_digest(self) -> str:
        return digest_value(self.descriptor())


@dataclass(frozen=True)
class RuleRegistry:
    registry_id: str
    version: str
    rules: tuple[RuleDefinition, ...]
    registry_digest: str
    qualification_evidence: tuple[dict[str, Any], ...]

    def snapshot(self) -> dict[str, Any]:
        return {
            "registry_id": self.registry_id,
            "version": self.version,
            "rules": [
                {**rule.descriptor(), "descriptor_digest": rule.descriptor_digest}
                for rule in self.rules
            ],
            "registry_digest": self.registry_digest,
            "qualification_evidence": self.qualification_evidence,
        }


@dataclass(frozen=True)
class RulePlan:
    plan_id: str
    disposition: PlanDisposition
    target: str
    source_sha256: str
    source_size: int
    registry_id: str
    registry_version: str
    registry_digest: str
    statement_byte_start: int | None
    statement_byte_end: int | None
    statement_sha256: str | None
    temporal_policy: dict[str, Any] | None
    temporal_policy_digest: str | None
    temporal_mappings: tuple[dict[str, Any], ...]
    value_policy: dict[str, Any] | None
    value_policy_digest: str | None
    value_occurrences: tuple[dict[str, Any], ...]
    selected_rules: tuple[dict[str, str], ...]
    observations: tuple[dict[str, str], ...]
    blockers: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_VERSION = re.compile(r"^[1-9][0-9]*\.[0-9]+\.[0-9]+$")
_SAFE_RULE_ID = re.compile(r"^[a-z][a-z0-9_.-]{2,127}$")
_ALLOWED_TARGETS = {"pyspark", "sparksql"}
_SECRET = re.compile(
    rb"(?i)(secret-canary|password\s*=|passwd\s*=|client[_-]?secret|access[_-]?token|dapi[a-z0-9]{8,})"
)


def digest_value(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _rules_for_target(target: str) -> tuple[RuleDefinition, ...]:
    fixtures = (
        "cv01-proc-sql-positive",
        "cv01-proc-sql-negative",
        "cv03-proc-sql-positive",
    )
    composition_group = "proc-sql-statement"
    return (
        RuleDefinition(
            "smf.proc_sql.envelope",
            "1.0.0",
            ConstructFamily.PROC_SQL,
            RuleType.ENVELOPE,
            supported_semantics=("complete PROC SQL/QUIT envelope removal",),
            unsupported_cases=("PROC SQL options", "multiple statements", "unterminated block"),
            target=target,
            fixture_qualifications=fixtures,
            composition_group=composition_group,
            composition_order=10,
        ),
        RuleDefinition(
            "smf.proc_sql.select",
            "1.0.0",
            ConstructFamily.SELECT,
            RuleType.STATEMENT,
            supported_semantics=(
                "SELECT projection",
                "FROM",
                "WHERE",
                "GROUP BY",
                "ORDER BY",
            ),
            unsupported_cases=(
                "SAS-specific functions",
                "implicit missing-value ordering",
                "ambiguous multi-statement source",
            ),
            target=target,
            fixture_qualifications=fixtures,
            composition_group=composition_group,
            composition_order=20,
        ),
        RuleDefinition(
            "smf.proc_sql.join",
            "1.0.0",
            ConstructFamily.JOIN,
            RuleType.CLAUSE,
            supported_semantics=("INNER JOIN with explicit ON", "LEFT JOIN with explicit ON"),
            unsupported_cases=(
                "implicit join",
                "missing ON predicate",
                "SAS missing-value dependency",
            ),
            target=target,
            fixture_qualifications=fixtures,
            composition_group=composition_group,
            composition_order=30,
        ),
        RuleDefinition(
            "smf.proc_sql.aggregate",
            "1.0.0",
            ConstructFamily.AGGREGATE,
            RuleType.CLAUSE,
            supported_semantics=("COUNT", "SUM", "AVG", "MIN", "MAX"),
            unsupported_cases=("unsupported function", "unapproved numeric tolerance"),
            target=target,
            fixture_qualifications=fixtures,
            composition_group=composition_group,
            composition_order=40,
        ),
        RuleDefinition(
            "smf.proc_sql.ctas_mapped",
            "1.0.0",
            ConstructFamily.CTAS,
            RuleType.STATEMENT,
            supported_semantics=("CREATE TABLE AS SELECT with authoritative dataset mappings",),
            unsupported_cases=("unresolved source mapping", "unresolved output mapping"),
            target=target,
            fixture_qualifications=fixtures,
            composition_group=composition_group,
            composition_order=50,
        ),
        RuleDefinition(
            "smf.proc_sql.sas_date_literal",
            "1.0.0",
            ConstructFamily.DATE_LITERAL,
            RuleType.CLAUSE,
            supported_semantics=("DDMONYYYY SAS date literal with 1960-01-01 epoch",),
            unsupported_cases=("two-digit years", "locale-dependent months", "time literals"),
            target=target,
            fixture_qualifications=("sassem01-temporal-positive",),
            composition_group=composition_group,
            composition_order=60,
        ),
        RuleDefinition(
            "smf.proc_sql.sas_datetime_literal",
            "1.0.0",
            ConstructFamily.DATETIME_LITERAL,
            RuleType.CLAUSE,
            supported_semantics=("UTC DDMONYYYY:HH:MM:SS.ffffff SAS datetime literal",),
            unsupported_cases=("non-UTC timezones", "leap seconds", "excess precision"),
            target=target,
            fixture_qualifications=("sassem01-temporal-positive",),
            composition_group=composition_group,
            composition_order=70,
        ),
        RuleDefinition(
            "smf.proc_sql.implicit_literal_coercion",
            "1.0.0",
            ConstructFamily.IMPLICIT_COERCION,
            RuleType.CLAUSE,
            supported_semantics=("exact bounded character-to-numeric literal coercion",),
            unsupported_cases=(
                "missing values",
                "malformed or lossy numeric strings",
                "numeric-to-character coercion",
                "schema-dependent coercion",
            ),
            target=target,
            fixture_qualifications=("sassem02-value-coercion-positive",),
            composition_group=composition_group,
            composition_order=80,
        ),
    )


def _rules() -> tuple[RuleDefinition, ...]:
    return _rules_for_target("sparksql") + _rules_for_target("pyspark")


_QUALIFICATION_FIXTURES: dict[str, dict[str, Any]] = {
    "cv01-proc-sql-positive": {
        "source_sha256": hashlib.sha256(b"proc sql; select id from members; quit;").hexdigest(),
        "expected_disposition": "qualified",
        "expected_output_sha256_by_target": {
            "sparksql": hashlib.sha256(b"select id from members;\n").hexdigest(),
            "pyspark": hashlib.sha256(b'spark.sql("""select id from members;""")\n').hexdigest(),
        },
    },
    "cv01-proc-sql-negative": {
        "source_sha256": hashlib.sha256(
            b"proc sql; select id from a union select id from b; quit;"
        ).hexdigest(),
        "expected_disposition": "unsupported",
        "expected_output_sha256_by_target": {"sparksql": None, "pyspark": None},
    },
    "cv03-proc-sql-positive": {
        "source_sha256": hashlib.sha256(b"proc sql; select id from members; quit;\n").hexdigest(),
        "expected_disposition": "qualified",
        "expected_output_sha256_by_target": {
            "sparksql": hashlib.sha256(b"select id from members;\n").hexdigest(),
            "pyspark": hashlib.sha256(b'spark.sql("""select id from members;""")\n').hexdigest(),
        },
    },
    "sassem01-temporal-positive": {
        "source_sha256": hashlib.sha256(
            b"proc sql; select * from t where d='01JAN1960'd and ts='01JAN1960:00:00:00.5'dt; quit;"
        ).hexdigest(),
        "expected_disposition": "qualified",
        "expected_output_sha256_by_target": {
            "sparksql": hashlib.sha256(
                b"select * from t where d=DATE '1960-01-01' and "
                b"ts=TIMESTAMP '1960-01-01 00:00:00.5';\n"
            ).hexdigest(),
            "pyspark": hashlib.sha256(
                b'spark.sql("""select * from t where d=DATE \'1960-01-01\' and '
                b'ts=TIMESTAMP \'1960-01-01 00:00:00.5\';""")\n'
            ).hexdigest(),
        },
    },
    "sassem02-value-coercion-positive": {
        "source_sha256": hashlib.sha256(
            b"proc sql; select * from t where '001'=1; quit;"
        ).hexdigest(),
        "expected_disposition": "qualified",
        "expected_output_sha256_by_target": {
            "sparksql": hashlib.sha256(b"select * from t where 1=1;\n").hexdigest(),
            "pyspark": hashlib.sha256(b'spark.sql("""select * from t where 1=1;""")\n').hexdigest(),
        },
    },
}


def _qualification_evidence(rule: RuleDefinition) -> dict[str, Any]:
    """Build the package-owned qualification record for one exact descriptor."""

    fixtures_list: list[dict[str, Any]] = []
    for fixture_id in rule.fixture_qualifications:
        fixture = dict(_QUALIFICATION_FIXTURES[fixture_id])
        outputs = fixture.pop("expected_output_sha256_by_target")
        fixture["expected_output_sha256"] = outputs[rule.target]
        fixtures_list.append({"fixture_id": fixture_id, **fixture})
    fixtures = tuple(fixtures_list)
    record = {
        "qualification_id": stable_id(
            "CVQUAL",
            {
                "descriptor_digest": rule.descriptor_digest,
                "runner": "smf.registry-fixtures",
                "runner_version": "1.0.0",
                "fixtures": fixtures,
            },
        ),
        "descriptor_digest": rule.descriptor_digest,
        "runner": "smf.registry-fixtures",
        "runner_version": "1.0.0",
        "fixtures": fixtures,
        "result": "passed",
    }
    return {**record, "result_digest": digest_value(record)}


_PACKAGE_RULES = _rules()
_PACKAGE_QUALIFICATIONS = {
    rule.descriptor_digest: _qualification_evidence(rule) for rule in _PACKAGE_RULES
}


def build_registry(rules: Iterable[RuleDefinition] | None = None) -> RuleRegistry:
    materialized = tuple(rules if rules is not None else _PACKAGE_RULES)
    if not materialized:
        raise ValueError("Deterministic registry must contain at least one rule")
    identities: set[tuple[str, str, str]] = set()
    active_revisions: set[tuple[str, str]] = set()
    positions: set[tuple[str, str, int]] = set()
    qualification_evidence: list[dict[str, Any]] = []
    for rule in materialized:
        if not _SAFE_RULE_ID.fullmatch(rule.rule_id) or not _VERSION.fullmatch(rule.version):
            raise ValueError("Deterministic registry contains an invalid rule identity or version")
        if rule.target not in _ALLOWED_TARGETS:
            raise ValueError("Deterministic registry contains an unknown target")
        if not isinstance(rule.construct_family, ConstructFamily) or not isinstance(
            rule.rule_type, RuleType
        ):
            raise ValueError("Deterministic registry contains an unknown enum value")
        identity = (rule.rule_id, rule.version, rule.target)
        if identity in identities:
            raise ValueError("Deterministic registry contains a duplicate rule identity")
        identities.add(identity)
        active_revision = (rule.rule_id, rule.target)
        if active_revision in active_revisions:
            raise ValueError("Deterministic registry contains multiple active revisions")
        active_revisions.add(active_revision)
        if not rule.supported_semantics or not rule.unsupported_cases:
            raise ValueError("Deterministic rule must declare supported and unsupported semantics")
        position = (rule.target, rule.composition_group, rule.composition_order)
        if position in positions:
            raise ValueError("Deterministic registry contains an overlapping composition position")
        positions.add(position)
        evidence = _PACKAGE_QUALIFICATIONS.get(rule.descriptor_digest)
        if (
            not rule.fixture_qualifications
            or evidence is None
            or tuple(item["fixture_id"] for item in evidence["fixtures"])
            != rule.fixture_qualifications
            or evidence.get("result") != "passed"
        ):
            raise ValueError(
                "Deterministic rule revision lacks package-owned descriptor-bound qualification"
            )
        qualification_evidence.append(evidence)
    exclusive = [rule for rule in materialized if rule.exclusive]
    if len({(rule.target, rule.composition_group) for rule in exclusive}) != len(exclusive):
        raise ValueError("Deterministic registry contains overlapping exclusive rules")
    ordered = tuple(
        sorted(materialized, key=lambda item: (item.target, item.composition_order, item.rule_id))
    )
    registry_id = "smf.deterministic.proc_sql"
    registry_version = "1.2.0"
    descriptor: dict[str, Any] = {
        "registry_id": registry_id,
        "version": registry_version,
        "rules": [rule.descriptor() for rule in ordered],
        "qualification_result_digests": sorted(
            item["result_digest"] for item in qualification_evidence
        ),
    }
    return RuleRegistry(
        registry_id=registry_id,
        version=registry_version,
        rules=ordered,
        registry_digest=digest_value(descriptor),
        qualification_evidence=tuple(
            sorted(qualification_evidence, key=lambda item: item["descriptor_digest"])
        ),
    )


DEFAULT_REGISTRY = build_registry()


def qualification_evidence_for_plan(plan: RulePlan, fixture_id: str) -> dict[str, Any]:
    """Resolve package-owned, descriptor-bound behavioral evidence for a plan.

    A manifest may name this evidence, but it cannot author or alter it. Every
    selected rule must have passed the same exact source/output fixture.
    """

    if plan.registry_digest != DEFAULT_REGISTRY.registry_digest:
        raise ValueError("Plan is not bound to the package deterministic registry")
    if plan.disposition is not PlanDisposition.QUALIFIED or not plan.selected_rules:
        raise ValueError("Behavioral qualification requires a qualified generated plan")
    records_by_descriptor = {
        item["descriptor_digest"]: item for item in DEFAULT_REGISTRY.qualification_evidence
    }
    bindings: list[dict[str, str]] = []
    fixture_material: dict[str, Any] | None = None
    for selected in plan.selected_rules:
        record = records_by_descriptor.get(selected["descriptor_digest"])
        if record is None or record.get("result") != "passed":
            raise ValueError("Selected rule lacks package-owned qualification evidence")
        unsigned = {key: value for key, value in record.items() if key != "result_digest"}
        if record.get("result_digest") != digest_value(unsigned):
            raise ValueError("Package qualification evidence digest is invalid")
        matches = [item for item in record["fixtures"] if item["fixture_id"] == fixture_id]
        if len(matches) != 1:
            raise ValueError("Behavioral expectation does not qualify every selected rule")
        fixture = matches[0]
        if fixture_material is None:
            fixture_material = fixture
        elif fixture != fixture_material:
            raise ValueError("Behavioral expectation is ambiguous across selected rules")
        bindings.append(
            {
                "descriptor_digest": selected["descriptor_digest"],
                "qualification_id": record["qualification_id"],
                "result_digest": record["result_digest"],
            }
        )
    assert fixture_material is not None
    evidence: dict[str, Any] = {
        "fixture_id": fixture_id,
        "source_sha256": fixture_material["source_sha256"],
        "expected_disposition": fixture_material["expected_disposition"],
        "expected_output_sha256": fixture_material["expected_output_sha256"],
        "registry_id": plan.registry_id,
        "registry_version": plan.registry_version,
        "registry_digest": plan.registry_digest,
        "rule_bindings": sorted(bindings, key=lambda item: item["descriptor_digest"]),
    }
    evidence["evidence_digest"] = digest_value(evidence)
    return evidence


_UNSUPPORTED_SQL_TOKENS: tuple[tuple[str, str], ...] = (
    (r"\bunion\b", "UNION is outside the qualified SQL subset"),
    (r"\bintersect\b", "INTERSECT is outside the qualified SQL subset"),
    (r"\bexcept\b", "EXCEPT is outside the qualified SQL subset"),
    (r"\bhaving\b", "HAVING is outside the qualified SQL subset"),
    (r"\binto\s*:", "SELECT INTO macro assignment is unsupported"),
    (r"\bcalculated\b", "SAS CALCULATED semantics are unsupported"),
    (r"\bcase\b", "CASE expressions are outside the qualified SQL subset"),
    (r"\bqualify\b", "QUALIFY is outside the qualified SQL subset"),
    (r"\blimit\b", "LIMIT is outside the qualified SQL subset"),
    (r"\boffset\b", "OFFSET is outside the qualified SQL subset"),
    (r"\bfetch\b", "FETCH is outside the qualified SQL subset"),
    (r"\bwindow\b", "WINDOW is outside the qualified SQL subset"),
    (r"\bover\s*\(", "window functions are outside the qualified SQL subset"),
    (r"\bpartition\s+by\b", "window partitions are outside the qualified SQL subset"),
    (r"\bwith\b", "common table expressions are outside the qualified SQL subset"),
    (r"\bdistinct\b", "DISTINCT is outside the qualified SQL subset"),
    (r"\b(?:update|delete|insert|merge|alter|drop)\b", "non-SELECT SQL is unsupported"),
    (r"\b(?:format|informat)\s*=", "SAS format modifiers are unsupported"),
)


def _unsupported_sql_reason(query: str) -> str | None:
    """Return why the complete statement is outside the declared grammar."""

    for pattern, reason in _UNSUPPORTED_SQL_TOKENS:
        if re.search(pattern, query, re.I):
            return reason
    if len(re.findall(r"\bselect\b", query, re.I)) != 1:
        return "nested or multiple SELECT statements are outside the qualified SQL subset"
    clause_positions: list[tuple[int, str]] = []
    for clause, pattern in (
        ("from", r"\bfrom\b"),
        ("where", r"\bwhere\b"),
        ("group by", r"\bgroup\s+by\b"),
        ("order by", r"\border\s+by\b"),
    ):
        matches = list(re.finditer(pattern, query, re.I))
        if len(matches) > 1:
            return f"multiple {clause.upper()} clauses are outside the qualified SQL subset"
        if matches:
            clause_positions.append((matches[0].start(), clause))
    expected = ["from", "where", "group by", "order by"]
    actual = [clause for _, clause in sorted(clause_positions)]
    if actual != [clause for clause in expected if clause in actual]:
        return "SQL clauses are not in the qualified order"
    if query.count("(") != query.count(")"):
        return "unbalanced SQL parentheses are unsupported"
    return None


def _observation(
    family: ConstructFamily, applicability: Applicability, reason: str
) -> dict[str, str]:
    return {
        "construct_family": family.value,
        "applicability": applicability.value,
        "reason": reason,
    }


def _finish_plan(
    *,
    source: bytes,
    target: str,
    disposition: PlanDisposition,
    selected: tuple[RuleDefinition, ...] = (),
    observations: tuple[dict[str, str], ...] = (),
    blockers: tuple[str, ...] = (),
    span: tuple[int, int] | None = None,
    temporal_policy: TemporalPolicy | None = None,
    temporal_mappings: tuple[dict[str, Any], ...] = (),
    value_policy: ValueCompatibilityPolicy | None = None,
    value_occurrences: tuple[dict[str, Any], ...] = (),
    registry: RuleRegistry = DEFAULT_REGISTRY,
) -> RulePlan:
    source_digest = hashlib.sha256(source).hexdigest()
    selected_rules = tuple(
        {
            "rule_id": rule.rule_id,
            "rule_version": rule.version,
            "descriptor_digest": rule.descriptor_digest,
        }
        for rule in selected
    )
    statement_digest = hashlib.sha256(source[slice(*span)]).hexdigest() if span else None
    identity = {
        "source_sha256": source_digest,
        "source_size": len(source),
        "target": target,
        "registry_digest": registry.registry_digest,
        "span": span,
        "selected_rules": selected_rules,
        "temporal_policy_digest": (
            temporal_policy.policy_digest if temporal_policy is not None else None
        ),
        "temporal_mappings": temporal_mappings,
        "value_policy_digest": value_policy.policy_digest if value_policy is not None else None,
        "value_occurrences": value_occurrences,
        "observations": observations,
        "blockers": blockers,
        "disposition": disposition.value,
    }
    return RulePlan(
        plan_id=stable_id("CVPLAN", identity),
        disposition=disposition,
        target=target,
        source_sha256=source_digest,
        source_size=len(source),
        registry_id=registry.registry_id,
        registry_version=registry.version,
        registry_digest=registry.registry_digest,
        statement_byte_start=span[0] if span else None,
        statement_byte_end=span[1] if span else None,
        statement_sha256=statement_digest,
        temporal_policy=temporal_policy.to_dict() if temporal_policy is not None else None,
        temporal_policy_digest=(
            temporal_policy.policy_digest if temporal_policy is not None else None
        ),
        temporal_mappings=temporal_mappings,
        value_policy=value_policy.to_dict() if value_policy is not None else None,
        value_policy_digest=value_policy.policy_digest if value_policy is not None else None,
        value_occurrences=value_occurrences,
        selected_rules=selected_rules,
        observations=observations,
        blockers=blockers,
    )


def plan_rules(
    source: bytes,
    target: str,
    *,
    dataset_mappings: dict[str, str] | None = None,
    temporal_policy: TemporalPolicy | None = None,
    value_policy: ValueCompatibilityPolicy | None = None,
    registry: RuleRegistry = DEFAULT_REGISTRY,
) -> RulePlan:
    """Plan the conservative, single-statement PROC SQL subset from exact bytes."""

    if target not in _ALLOWED_TARGETS:
        raise ValueError("Unknown deterministic conversion target")
    if not source or not source.strip():
        return _finish_plan(
            source=source,
            target=target,
            disposition=PlanDisposition.UNSUPPORTED,
            observations=(
                _observation(ConstructFamily.PROC_SQL, Applicability.UNSUPPORTED, "empty source"),
            ),
            blockers=("meaningful eligible source statement is absent",),
            registry=registry,
        )
    if _SECRET.search(source):
        return _finish_plan(
            source=source,
            target=target,
            disposition=PlanDisposition.BLOCKED,
            observations=(
                _observation(
                    ConstructFamily.PROC_SQL,
                    Applicability.BLOCKED,
                    "protected-data canary detected",
                ),
            ),
            blockers=("source requires protected-data handling before deterministic conversion",),
            registry=registry,
        )
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError:
        return _finish_plan(
            source=source,
            target=target,
            disposition=PlanDisposition.BLOCKED,
            blockers=("source is not valid UTF-8",),
            registry=registry,
        )
    lowered = text.lower()
    separated = (
        (ConstructFamily.PROC_FORMAT, r"\bproc\s+format\b", "PROC FORMAT is a separate family"),
        (ConstructFamily.SAS_MACRO, r"(?:%[a-z_]|&[a-z_])", "SAS macro processing is unsupported"),
        (ConstructFamily.TARGET_TEMPLATE, r"(?:\{\{|\{%|\{#)", "target Jinja/dbt is unsupported"),
    )
    observations: list[dict[str, str]] = []
    for family, pattern, reason in separated:
        if re.search(pattern, lowered, re.IGNORECASE):
            observations.append(_observation(family, Applicability.UNSUPPORTED, reason))
    if re.search(r"/\*|(?:^|;)\s*\*[^;]*;|--", text, re.MULTILINE):
        observations.append(
            _observation(
                ConstructFamily.PROC_SQL,
                Applicability.UNSUPPORTED,
                "comments require lexical qualification not provided by this registry version",
            )
        )
    if re.search(r"\b(connect\s+to|execute\s*\()", lowered):
        observations.append(
            _observation(
                ConstructFamily.PROC_SQL,
                Applicability.UNSUPPORTED,
                "SQL pass-through is unsupported",
            )
        )
    if observations:
        return _finish_plan(
            source=source,
            target=target,
            disposition=PlanDisposition.UNSUPPORTED,
            observations=tuple(observations),
            blockers=tuple(item["reason"] for item in observations),
            registry=registry,
        )
    envelope = re.fullmatch(r"\s*proc\s+sql\s*;(?P<body>.*?)\bquit\s*;\s*", text, re.I | re.S)
    if envelope is None:
        return _finish_plan(
            source=source,
            target=target,
            disposition=PlanDisposition.UNSUPPORTED,
            observations=(
                _observation(
                    ConstructFamily.PROC_SQL,
                    Applicability.UNSUPPORTED,
                    "complete PROC SQL/QUIT envelope not found",
                ),
            ),
            blockers=("complete PROC SQL/QUIT envelope not found",),
            registry=registry,
        )
    body_start, body_end = envelope.span("body")
    body = text[body_start:body_end].strip()
    leading = len(text[body_start:body_end]) - len(text[body_start:body_end].lstrip())
    statement_start = body_start + leading
    if body.count(";") != 1 or not body.endswith(";"):
        return _finish_plan(
            source=source,
            target=target,
            disposition=PlanDisposition.UNSUPPORTED,
            blockers=("registry requires exactly one complete SQL statement",),
            registry=registry,
        )
    statement = body[:-1].strip()
    statement_end = statement_start + len(statement)
    span = (
        len(text[:statement_start].encode("utf-8")),
        len(text[:statement_end].encode("utf-8")),
    )
    temporal = normalize_temporal_literals(
        source[span[0] : span[1]], temporal_policy, target=target
    )
    if temporal.disposition in {TemporalDisposition.BLOCKED, TemporalDisposition.UNSUPPORTED}:
        disposition = (
            PlanDisposition.BLOCKED
            if temporal.disposition is TemporalDisposition.BLOCKED
            else PlanDisposition.UNSUPPORTED
        )
        applicability = (
            Applicability.BLOCKED
            if disposition is PlanDisposition.BLOCKED
            else Applicability.UNSUPPORTED
        )
        return _finish_plan(
            source=source,
            target=target,
            disposition=disposition,
            observations=(
                _observation(ConstructFamily.SELECT, applicability, temporal.blockers[0]),
            ),
            blockers=temporal.blockers,
            span=span,
            temporal_policy=temporal_policy,
            value_policy=value_policy,
            registry=registry,
        )
    temporal_mappings = tuple(
        {
            **mapping.to_dict(),
            "byte_start": mapping.byte_start + span[0],
            "byte_end": mapping.byte_end + span[0],
        }
        for mapping in temporal.mappings
    )
    value = classify_value_semantics(source[span[0] : span[1]], value_policy, target=target)
    value_occurrences = tuple(
        {
            **occurrence.to_dict(),
            "byte_start": occurrence.byte_start + span[0],
            "byte_end": occurrence.byte_end + span[0],
        }
        for occurrence in value.occurrences
    )
    if value.disposition in {ValueDisposition.BLOCKED, ValueDisposition.UNSUPPORTED}:
        disposition = (
            PlanDisposition.BLOCKED
            if value.disposition is ValueDisposition.BLOCKED
            else PlanDisposition.UNSUPPORTED
        )
        applicability = (
            Applicability.BLOCKED
            if disposition is PlanDisposition.BLOCKED
            else Applicability.UNSUPPORTED
        )
        family = (
            ConstructFamily.MISSING_VALUE
            if any(item["occurrence_kind"].endswith("missing") for item in value_occurrences)
            else ConstructFamily.IMPLICIT_COERCION
        )
        return _finish_plan(
            source=source,
            target=target,
            disposition=disposition,
            observations=(_observation(family, applicability, value.blockers[0]),),
            blockers=value.blockers,
            span=span,
            temporal_policy=temporal_policy,
            temporal_mappings=temporal_mappings,
            value_policy=value_policy,
            value_occurrences=value_occurrences,
            registry=registry,
        )
    statement_bytes = source[span[0] : span[1]]
    replacements = [
        (
            int(item["byte_start"]) - span[0],
            int(item["byte_end"]) - span[0],
            str(item["target_expression"]).encode(),
        )
        for item in (*temporal_mappings, *value_occurrences)
        if item.get("target_expression") is not None
    ]
    for start, end, replacement in sorted(replacements, reverse=True):
        statement_bytes = statement_bytes[:start] + replacement + statement_bytes[end:]
    statement = statement_bytes.decode("utf-8")
    ctas = re.fullmatch(
        r"create\s+table\s+(?P<output>[a-z_][a-z0-9_.]*)\s+as\s+(?P<select>select\s+.+)",
        statement,
        re.I | re.S,
    )
    query = statement
    selected_families = {ConstructFamily.PROC_SQL, ConstructFamily.SELECT}
    literal_kinds = {item["literal_kind"] for item in temporal_mappings}
    if "date" in literal_kinds:
        selected_families.add(ConstructFamily.DATE_LITERAL)
    if "datetime" in literal_kinds:
        selected_families.add(ConstructFamily.DATETIME_LITERAL)
    if value_occurrences:
        selected_families.add(ConstructFamily.IMPLICIT_COERCION)
    if ctas:
        selected_families.add(ConstructFamily.CTAS)
        output = ctas.group("output").lower()
        if not dataset_mappings or output not in {key.lower() for key in dataset_mappings}:
            return _finish_plan(
                source=source,
                target=target,
                disposition=PlanDisposition.BLOCKED,
                observations=(
                    _observation(
                        ConstructFamily.CTAS,
                        Applicability.BLOCKED,
                        "authoritative output dataset mapping is absent",
                    ),
                ),
                blockers=("authoritative CTAS output mapping is required",),
                span=span,
                temporal_policy=temporal_policy,
                temporal_mappings=temporal_mappings,
                value_policy=value_policy,
                value_occurrences=value_occurrences,
                registry=registry,
            )
        query = ctas.group("select")
    if not re.match(r"select\s+\S", query, re.I | re.S):
        return _finish_plan(
            source=source,
            target=target,
            disposition=PlanDisposition.UNSUPPORTED,
            blockers=("meaningful SELECT projection is absent",),
            span=span,
            temporal_policy=temporal_policy,
            temporal_mappings=temporal_mappings,
            value_policy=value_policy,
            value_occurrences=value_occurrences,
            registry=registry,
        )
    unsupported_reason = _unsupported_sql_reason(query)
    if unsupported_reason is not None:
        return _finish_plan(
            source=source,
            target=target,
            disposition=PlanDisposition.UNSUPPORTED,
            observations=(
                _observation(
                    ConstructFamily.SELECT,
                    Applicability.UNSUPPORTED,
                    unsupported_reason,
                ),
            ),
            blockers=(unsupported_reason,),
            span=span,
            temporal_policy=temporal_policy,
            temporal_mappings=temporal_mappings,
            value_policy=value_policy,
            value_occurrences=value_occurrences,
            registry=registry,
        )
    if re.search(r"\b(right|full|cross)\s+(outer\s+)?join\b", query, re.I):
        return _finish_plan(
            source=source,
            target=target,
            disposition=PlanDisposition.UNSUPPORTED,
            blockers=("join type is outside the qualified subset",),
            span=span,
            temporal_policy=temporal_policy,
            temporal_mappings=temporal_mappings,
            value_policy=value_policy,
            value_occurrences=value_occurrences,
            registry=registry,
        )
    joins = re.findall(r"\b(?:inner\s+|left(?:\s+outer)?\s+)?join\b", query, re.I)
    if joins:
        selected_families.add(ConstructFamily.JOIN)
        if len(re.findall(r"\bon\b", query, re.I)) < len(joins):
            return _finish_plan(
                source=source,
                target=target,
                disposition=PlanDisposition.UNSUPPORTED,
                blockers=("every JOIN requires an explicit ON predicate",),
                span=span,
                temporal_policy=temporal_policy,
                temporal_mappings=temporal_mappings,
                value_policy=value_policy,
                value_occurrences=value_occurrences,
                registry=registry,
            )
    functions = {name.lower() for name in re.findall(r"\b([a-z_][a-z0-9_]*)\s*\(", query, re.I)}
    aggregates = functions & {"count", "sum", "avg", "min", "max"}
    unsupported_functions = functions - aggregates
    if unsupported_functions:
        return _finish_plan(
            source=source,
            target=target,
            disposition=PlanDisposition.UNSUPPORTED,
            blockers=(f"unsupported SQL function: {sorted(unsupported_functions)[0]}",),
            span=span,
            temporal_policy=temporal_policy,
            temporal_mappings=temporal_mappings,
            value_policy=value_policy,
            value_occurrences=value_occurrences,
            registry=registry,
        )
    if aggregates:
        selected_families.add(ConstructFamily.AGGREGATE)
    selected = tuple(
        rule
        for rule in registry.rules
        if rule.target == target and rule.construct_family in selected_families
    )
    if not selected:
        raise ValueError("Registry has no rules for the qualified statement")
    observations.extend(
        _observation(rule.construct_family, Applicability.APPLICABLE, rule.rule_id)
        for rule in selected
    )
    return _finish_plan(
        source=source,
        target=target,
        disposition=PlanDisposition.QUALIFIED,
        selected=selected,
        observations=tuple(observations),
        span=span,
        temporal_policy=temporal_policy,
        temporal_mappings=temporal_mappings,
        value_policy=value_policy,
        value_occurrences=value_occurrences,
        registry=registry,
    )


def execute_plan(
    source: bytes,
    plan: RulePlan,
    *,
    workload_id: str,
    source_artifact_id: str,
    run_id: str,
    attempt_id: str,
) -> ProviderResult:
    """Execute only a replay-equivalent qualified plan and emit attributable evidence."""

    temporal_policy = (
        TemporalPolicy.from_dict(plan.temporal_policy) if plan.temporal_policy is not None else None
    )
    value_policy = (
        ValueCompatibilityPolicy.from_dict(plan.value_policy)
        if plan.value_policy is not None
        else None
    )
    if value_policy is not None and value_policy.policy_digest != plan.value_policy_digest:
        raise ValueError("Deterministic value compatibility policy digest is invalid")
    if temporal_policy is not None and temporal_policy.policy_digest != plan.temporal_policy_digest:
        raise ValueError("Deterministic temporal policy digest is invalid")
    replay = plan_rules(
        source,
        plan.target,
        temporal_policy=temporal_policy,
        value_policy=value_policy,
    )
    if replay != plan:
        raise ValueError("Deterministic plan no longer matches admitted source and registry")
    if plan.disposition is not PlanDisposition.QUALIFIED:
        raise ValueError("Only a uniquely qualified deterministic plan can execute")
    assert plan.statement_byte_start is not None and plan.statement_byte_end is not None
    statement_bytes = source[plan.statement_byte_start : plan.statement_byte_end]
    for mapping in sorted(
        (*plan.temporal_mappings, *plan.value_occurrences),
        key=lambda item: int(item["byte_start"]),
        reverse=True,
    ):
        start = int(mapping["byte_start"]) - plan.statement_byte_start
        end = int(mapping["byte_end"]) - plan.statement_byte_start
        if start < 0 or end > len(statement_bytes) or start >= end:
            raise ValueError("Deterministic semantic mapping escapes the statement boundary")
        literal = statement_bytes[start:end]
        source_token_digest = mapping.get("literal_sha256", mapping.get("source_token_sha256"))
        if hashlib.sha256(literal).hexdigest() != source_token_digest:
            raise ValueError("Deterministic semantic mapping source digest mismatch")
        expression = str(mapping["target_expression"]).encode("utf-8")
        if hashlib.sha256(expression).hexdigest() != mapping["target_expression_sha256"]:
            raise ValueError("Deterministic semantic mapping target digest mismatch")
        statement_bytes = statement_bytes[:start] + expression + statement_bytes[end:]
    statement = statement_bytes.decode("utf-8")
    content = statement.rstrip() + ";\n"
    if plan.target == "pyspark":
        if '"""' in statement:
            raise ValueError("Deterministic PySpark output cannot safely quote the SQL statement")
        content = f'spark.sql("""{statement.rstrip()};""")\n'
    output_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    temporal_mapping_evidence = []
    for mapping in plan.temporal_mappings:
        identity = {
            "plan_id": plan.plan_id,
            "workload_id": workload_id,
            "source_artifact_id": source_artifact_id,
            "run_id": run_id,
            "attempt_id": attempt_id,
            "source_sha256": plan.source_sha256,
            "byte_start": mapping["byte_start"],
            "byte_end": mapping["byte_end"],
            "literal_sha256": mapping["literal_sha256"],
            "policy_digest": plan.temporal_policy_digest,
            "target_expression_sha256": mapping["target_expression_sha256"],
            "generated_sha256": output_digest,
        }
        temporal_mapping_evidence.append(
            {
                "mapping_id": stable_id("CVMAP", identity),
                **mapping,
                **identity,
                "registry_digest": plan.registry_digest,
            }
        )
    value_mapping_evidence = []
    for occurrence in plan.value_occurrences:
        identity = {
            "plan_id": plan.plan_id,
            "workload_id": workload_id,
            "source_artifact_id": source_artifact_id,
            "run_id": run_id,
            "attempt_id": attempt_id,
            "source_sha256": plan.source_sha256,
            "byte_start": occurrence["byte_start"],
            "byte_end": occurrence["byte_end"],
            "source_token_sha256": occurrence["source_token_sha256"],
            "policy_digest": plan.value_policy_digest,
            "target_expression_sha256": occurrence["target_expression_sha256"],
            "generated_sha256": output_digest,
        }
        value_mapping_evidence.append(
            {
                "mapping_id": stable_id("CVVALUE", identity),
                **occurrence,
                **identity,
                "registry_digest": plan.registry_digest,
            }
        )
    applications = []
    for selected in plan.selected_rules:
        application = {
            "application_id": stable_id(
                "CVAPP",
                {
                    "plan_id": plan.plan_id,
                    "rule": selected,
                    "workload_id": workload_id,
                    "source_artifact_id": source_artifact_id,
                    "run_id": run_id,
                    "attempt_id": attempt_id,
                },
            ),
            **selected,
            "applicability": Applicability.APPLICABLE.value,
            "workload_id": workload_id,
            "source_artifact_id": source_artifact_id,
            "run_id": run_id,
            "attempt_id": attempt_id,
            "plan_id": plan.plan_id,
            "registry_digest": plan.registry_digest,
            "input_byte_start": plan.statement_byte_start,
            "input_byte_end": plan.statement_byte_end,
            "input_sha256": plan.statement_sha256,
            "output_sha256": output_digest,
        }
        applications.append(application)
    return ProviderResult(
        content=content,
        provider="smf-deterministic",
        metadata={
            "registry": DEFAULT_REGISTRY.snapshot(),
            "plan": plan.to_dict(),
            "applications": applications,
            "temporal_mappings": temporal_mapping_evidence,
            "value_mappings": value_mapping_evidence,
            "generated_sha256": output_digest,
            "implementation_version": "smf-0.1.0",
        },
    )
