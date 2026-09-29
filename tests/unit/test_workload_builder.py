import json

from smf.discovery.models import DiscoveryResult
from smf.workload.builder import WorkloadBuilder
from smf.workload.models import (
    ArtifactKind,
    Confidence,
    DatasetKind,
    EvidenceMethod,
    RelationshipKind,
)


def test_builder_creates_evidence_backed_workload_graph() -> None:
    builder = WorkloadBuilder(name="claims-monthly", namespace="test")

    evidence = builder.evidence(
        method=EvidenceMethod.STATIC_ANALYSIS,
        source="monthly_claims.sas",
        confidence=Confidence.HIGH,
        locator="line 12",
        observed_value="set EDW.CLAIMS_HISTORY",
    )
    program = builder.add_artifact(
        kind=ArtifactKind.SAS_PROGRAM,
        name="monthly_claims.sas",
        logical_path="source/monthly_claims.sas",
        evidence=(evidence,),
    )
    dataset = builder.add_dataset(
        kind=DatasetKind.DATABASE_TABLE,
        name="CLAIMS_HISTORY",
        system="EDW",
        evidence=(evidence,),
    )
    relationship = builder.add_relationship(
        source_id=program.artifact_id,
        kind=RelationshipKind.READS,
        target_id=dataset.dataset_id,
        evidence=(evidence,),
    )

    workload = builder.build()

    assert workload.name == "claims-monthly"
    assert workload.workload_id.startswith("WL-")
    assert workload.artifacts == (program,)
    assert workload.datasets == (dataset,)
    assert workload.relationships == (relationship,)
    assert relationship.evidence[0].confidence is Confidence.HIGH


def test_builder_identity_does_not_depend_on_local_checkout_path() -> None:
    first = WorkloadBuilder(name="claims-monthly", namespace="humana")
    second = WorkloadBuilder(name="claims-monthly", namespace="humana")

    assert first.workload_id == second.workload_id


def test_canonical_workload_sanitizes_nested_evidence_before_serialization() -> None:
    canaries = {
        "source-canary",
        "observed-canary",
        "evidence-canary",
        "artifact-canary",
        "dataset-canary",
        "relationship-canary",
        "workload-canary",
        "shared-access-canary",
        "sas-signature-canary",
        "header-key-canary",
        "json-password-canary",
        "yaml-password-canary",
        "brace-password-canary",
        "upper-pair-canary",
        "key-pair-canary",
        "empty-userinfo-canary",
        # The trailing token specifically guards against partial redaction at
        # the first whitespace in an unquoted connection-string value.
        "phrase-canary",
        "userinfo-canary",
        "github-pat-canary",
        "rails-secret-canary",
        "unterminated phrase-canary",
        "github-token-field-canary",
        "session-token-field-canary",
        "bearer-token-field-canary",
        "spaced-final-canary",
        "token-scheme-canary",
        "password-value-canary",
        "snake-password-value-canary",
        "sequence-pair-canary",
        "oracle-canary",
    }
    builder = WorkloadBuilder(
        name="secure",
        metadata={
            "runtime": {
                "DB_PASSWORD": "workload-canary",
                "connection": "SharedAccessKey=shared-access-canary",
                "sas_url": "https://storage.example/blob?sig=sas-signature-canary&sp=r",
                "header": "X-API-Key: header-key-canary",
                "json": '{"password": "json-password-canary"}',
                "yaml": "password: yaml-password-canary",
                "odbc": "PWD={odbc;brace-password-canary}",
                "environment": [
                    {"Name": "DB_PASSWORD", "Value": "upper-pair-canary"},
                    {"key": "API_KEY", "value": "key-pair-canary"},
                    {"name": "GITHUB_PAT", "value": "github-pat-canary"},
                ],
                "SECRET_KEY_BASE": "rails-secret-canary",
                "githubToken": "github-token-field-canary",
                "sessionToken": "session-token-field-canary",
                "bearerToken": "bearer-token-field-canary",
                "passwordValue": "password-value-canary",
                "password_value": "snake-password-value-canary",
                "pair_environment": [["DB_PASSWORD", "sequence-pair-canary"]],
                "tokenCount": 17,
            }
        },
    )
    evidence = builder.evidence(
        method=EvidenceMethod.RUNTIME_METADATA,
        source="source.sas?token=source-canary",
        confidence=Confidence.HIGH,
        observed_value="Authorization: Bearer observed-canary",
        metadata={"deep": [{"client_secret": "evidence-canary"}]},
    )
    artifact = builder.add_artifact(
        kind=ArtifactKind.SAS_PROGRAM,
        name="secure.sas",
        evidence=(evidence,),
        metadata={"command": "--api-key artifact-canary sas -sysin secure.sas"},
    )
    dataset = builder.add_dataset(
        kind=DatasetKind.DATABASE_TABLE,
        name="CLAIMS",
        system="warehouse",
        evidence=(evidence,),
        metadata={"connection": "Server=db;Password=dataset-canary;Database=claims"},
    )
    builder.add_relationship(
        source_id=artifact.artifact_id,
        kind=RelationshipKind.READS,
        target_id=dataset.dataset_id,
        evidence=(evidence,),
        metadata={"environment": ["AUTH_TOKEN=relationship-canary"]},
    )

    # These reviewer-reported bypass forms sit in graph/evidence metadata so
    # the regression proves the canonical boundary protects derived output.
    builder.add_relationship(
        source_id=artifact.artifact_id,
        kind=RelationshipKind.DEPENDS_ON,
        target_id=dataset.dataset_id,
        evidence=(evidence,),
        metadata={
            "cache": "redis://:empty-userinfo-canary@cache.example/0",
            "connection": "Server=db;Password=spaced-prefix phrase-canary;Database=claims",
            "ssh": "ssh reporter:userinfo-canary@db.example",
            "trailing_connection": ("Server=db.example;Password=unterminated phrase-canary"),
            "spaced_trailing_connection": "Server=db; Password=prefix spaced-final-canary",
            "authorization_header": "Authorization: Token token-scheme-canary",
            "oracle_connection": ("jdbc:oracle:thin:reporter/oracle-canary@db.example:1521/claims"),
        },
    )

    workload = builder.build()
    durable_workload = workload.to_dict()
    serialized = json.dumps(durable_workload)
    durable_graph_and_evidence = json.dumps(
        {
            "relationships": durable_workload["relationships"],
            "topology": durable_workload["topology"],
            "artifact_evidence": [item["evidence"] for item in durable_workload["artifacts"]],
        }
    )

    assert not any(canary in serialized for canary in canaries)
    assert not any(canary in durable_graph_and_evidence for canary in canaries)
    assert "db" in serialized
    assert "cache.example" in serialized
    assert "claims" in serialized
    assert "secure.sas" in serialized
    assert durable_workload["metadata"]["runtime"]["tokenCount"] == 17


def test_evidence_identity_is_derived_from_sanitized_values() -> None:
    builder = WorkloadBuilder(name="secure")

    first = builder.evidence(
        method=EvidenceMethod.RUNTIME_METADATA,
        source="scheduler",
        confidence=Confidence.HIGH,
        observed_value="DB_PASSWORD=first-canary sas -sysin claims.sas",
    )
    second = builder.evidence(
        method=EvidenceMethod.RUNTIME_METADATA,
        source="scheduler",
        confidence=Confidence.HIGH,
        observed_value="DB_PASSWORD=second-canary sas -sysin claims.sas",
    )

    assert first.evidence_id == second.evidence_id
    assert first.observed_value == second.observed_value
    assert "first-canary" not in (first.observed_value or "")
    assert "second-canary" not in (second.observed_value or "")


def test_workload_serialization_resanitizes_mutated_nested_metadata() -> None:
    workload = WorkloadBuilder(name="secure", metadata={"host": "db.example"}).build()

    workload.metadata["DB_PASSWORD"] = "post-boundary-raw-canary"
    workload.metadata["payload"] = '{"githubToken":"nested-json-raw-canary"}'

    serialized = json.dumps(workload.to_dict())

    assert "post-boundary-raw-canary" not in serialized
    assert "nested-json-raw-canary" not in serialized
    assert serialized.count("<redacted>") == 2
    assert workload.metadata["host"] == "db.example"

    discovery_result = DiscoveryResult(
        provider="filesystem",
        source="safe/source",
        workloads=(workload,),
    )
    envelope = json.dumps(discovery_result.to_dict())

    assert "post-boundary-raw-canary" not in envelope
    assert "nested-json-raw-canary" not in envelope
