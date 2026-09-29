"""Acceptance regressions for SEC-05 canonical discovery secret sanitization."""

import json
from enum import StrEnum

import pytest

from smf.workload.builder import WorkloadBuilder
from smf.workload.models import (
    Confidence,
    DiscoveryEvidence,
    EvidenceMethod,
    ExternalDependencyKind,
    Relationship,
    RelationshipKind,
    Workload,
)
from smf.workload.sanitization import REDACTED, sanitize_discovery_value


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        (
            'DOCKER_AUTH_CONFIG={"auths":{"registry.example":{"auth":"docker-auth-canary"}}} '
            "sas -sysin claims.sas",
            "docker-auth-canary",
        ),
        ("password: correct horse battery staple", "correct horse battery staple"),
        (
            'Authorization: Digest username="reporter", realm="db", response="digest-canary"',
            'username="reporter", realm="db", response="digest-canary"',
        ),
    ],
)
def test_sec05_reviewer_bypasses_are_fully_redacted(raw: str, secret: str) -> None:
    sanitized = sanitize_discovery_value(raw)

    assert secret not in sanitized
    assert REDACTED in sanitized


def test_sec05_reviewer_bypasses_do_not_survive_canonical_serialization() -> None:
    evidence = DiscoveryEvidence(
        evidence_id="EV-SEC05",
        method=EvidenceMethod.SCHEDULER_METADATA,
        source="assessment",
        confidence=Confidence.HIGH,
        observed_value="password: correct horse battery staple",
    )
    relationship = Relationship(
        relationship_id="REL-SEC05",
        source_id="a",
        kind=RelationshipKind.DEPENDS_ON,
        target_id="b",
        evidence=(evidence,),
        metadata={
            "launch": (
                'DOCKER_AUTH_CONFIG={"auths":{"registry.example":'
                '{"auth":"docker-auth-canary"}}} sas -sysin claims.sas'
            ),
            "auth": (
                'Authorization: Digest username="reporter", realm="db", response="digest-canary"'
            ),
        },
    )
    workload = Workload(
        workload_id="WL-SEC05",
        name="claims",
        relationships=(relationship,),
    )

    serialized = json.dumps(workload.to_dict())

    assert "docker-auth-canary" not in serialized
    assert "correct horse battery staple" not in serialized
    assert "digest-canary" not in serialized
    assert REDACTED in serialized


def test_sec05_post_construction_mutation_is_sanitized_at_serialization() -> None:
    workload = Workload(workload_id="WL-SEC05-MUT", name="claims")
    workload.metadata["DB_PASSWORD"] = "post-boundary-canary"
    workload.metadata["payload"] = (
        '{"githubToken":"nested-json-canary","DOCKER_AUTH_CONFIG":"docker-config-canary"}'
    )

    serialized = json.dumps(workload.to_dict())

    assert "post-boundary-canary" not in serialized
    assert "nested-json-canary" not in serialized
    assert "docker-config-canary" not in serialized
    assert REDACTED in serialized


@pytest.mark.parametrize(
    ("raw", "forbidden", "retained"),
    [
        ("--password two words --host db.example", "two words", "--host db.example"),
        ("password=two words sas -sysin x.sas", "two words", "sas -sysin x.sas"),
        ("DB_PASSWORD: yaml two words", "yaml two words", "DB_PASSWORD:"),
        ("apiKey : secret with spaces", "secret with spaces", "apiKey :"),
        (
            'Proxy-Authorization: Digest username="reporter", realm="db", response="proxy-canary"',
            "proxy-canary",
            "Proxy-Authorization: Digest",
        ),
        ("sqlplus reporter/oracle-canary@db", "oracle-canary", "reporter/<redacted>@db"),
        (
            "postgres://reporter:p@ss@db.example/x",
            "p@ss",
            "postgres://reporter:<redacted>@db.example/x",
        ),
        ("MY_SECRET_FILE=/tmp/secret-canary", "/tmp/secret-canary", "MY_SECRET_FILE="),
    ],
)
def test_sec05_additional_adversarial_forms_are_fully_redacted(
    raw: str, forbidden: str, retained: str
) -> None:
    sanitized = sanitize_discovery_value(raw)

    assert forbidden not in sanitized
    assert REDACTED in sanitized
    assert retained in sanitized


def test_sec05_parseable_json_strings_are_recursively_sanitized() -> None:
    raw = (
        '{"githubToken":"json-token-canary",'
        '"nested":{"DOCKER_AUTH_CONFIG":"docker-json-canary"},'
        '"host":"db.example"}'
    )

    sanitized = sanitize_discovery_value(raw)

    assert "json-token-canary" not in sanitized
    assert "docker-json-canary" not in sanitized
    assert "db.example" in sanitized
    assert REDACTED in sanitized


def test_sec05_secret_name_classifier_preserves_safe_counters() -> None:
    sanitized = sanitize_discovery_value(
        {
            "tokenCount": 5,
            "accessTokenCount": 7,
            "DOCKER_AUTH_CONFIG": "docker-structured-canary",
            "MY_SECRET_FILE": "/tmp/file-canary",
        }
    )

    assert sanitized["tokenCount"] == 5
    assert sanitized["accessTokenCount"] == 7
    assert sanitized["DOCKER_AUTH_CONFIG"] == REDACTED
    assert sanitized["MY_SECRET_FILE"] == REDACTED


@pytest.mark.parametrize(
    "raw",
    [
        (
            '--authorization Digest username="reporter", response="auth-option-canary" '
            "--host db.example"
        ),
        "--authentication Token auth-option-canary --host db.example",
        "--auth ApiKey auth-option-canary --host db.example",
        'Authorization=Digest username="reporter", response="auth-option-canary" --host db.example',
    ],
)
def test_sec05_authentication_options_redact_complete_payload(raw: str) -> None:
    sanitized = sanitize_discovery_value(raw)
    serialized = json.dumps(
        Workload(workload_id="WL-AUTH", name="w", metadata={"command": raw}).to_dict()
    )

    assert "auth-option-canary" not in sanitized
    assert "auth-option-canary" not in serialized
    assert REDACTED in sanitized
    assert "--host db.example" in sanitized


def test_sec05_external_dependency_identity_is_secret_independent() -> None:
    ids: list[str] = []
    serialized_locations: list[str] = []
    for secret in ("alpha-canary", "beta-canary"):
        builder = WorkloadBuilder(name="w")
        dependency = builder.add_external_dependency(
            kind=ExternalDependencyKind.DATABASE_CONNECTION,
            name="claims",
            location=f"postgres://reporter:{secret}@db.example/claims",
        )
        workload = builder.build()
        ids.append(dependency.dependency_id)
        serialized_locations.append(workload.external_dependencies[0].location or "")

    assert ids[0] == ids[1]
    assert serialized_locations == [
        "postgres://reporter:<redacted>@db.example/claims",
        "postgres://reporter:<redacted>@db.example/claims",
    ]


def test_sec05_string_valued_enums_are_sanitized_before_serialization() -> None:
    class ProviderValue(StrEnum):
        COMMAND = "DB_PASSWORD=strenum-canary sas -sysin claims.sas"
        TOKEN = "Bearer strenum-bearer-canary"

    evidence = DiscoveryEvidence(
        evidence_id="EV-STR-ENUM",
        method=EvidenceMethod.RUNTIME_METADATA,
        source="provider",
        confidence=Confidence.HIGH,
        metadata={"nested": ProviderValue.TOKEN},
    )
    relationship = Relationship(
        relationship_id="REL-STR-ENUM",
        source_id="a",
        kind=RelationshipKind.DEPENDS_ON,
        target_id="b",
        evidence=(evidence,),
        metadata={"command": ProviderValue.COMMAND},
    )
    workload = Workload(
        workload_id="WL-STR-ENUM",
        name="claims",
        relationships=(relationship,),
        metadata={"credential": ProviderValue.COMMAND},
    )

    serialized = json.dumps(workload.to_dict())

    assert "strenum-canary" not in serialized
    assert "strenum-bearer-canary" not in serialized
    assert REDACTED in serialized


@pytest.mark.parametrize(
    ("raw", "forbidden", "retained"),
    [
        (
            r"DB_PASSWORD=prefix\ --LEAK_CANARY sas -sysin x.sas",
            "LEAK_CANARY",
            "sas -sysin x.sas",
        ),
        (
            r"DB_PASSWORD=prefix\;LEAK_CANARY sas -sysin x.sas",
            "LEAK_CANARY",
            "sas -sysin x.sas",
        ),
        (
            r"DB_PASSWORD=prefix\&LEAK_CANARY sas -sysin x.sas",
            "LEAK_CANARY",
            "sas -sysin x.sas",
        ),
        (
            r"--password prefix\ --LEAK_CANARY --host db.example",
            "LEAK_CANARY",
            "--host db.example",
        ),
    ],
)
def test_sec05_shell_escaped_secret_content_is_consumed(
    raw: str, forbidden: str, retained: str
) -> None:
    sanitized = sanitize_discovery_value(raw)
    serialized = json.dumps(
        Workload(workload_id="WL-ESCAPED", name="w", metadata={"command": raw}).to_dict()
    )

    assert forbidden not in sanitized
    assert forbidden not in serialized
    assert retained in sanitized
    assert REDACTED in sanitized


@pytest.mark.parametrize("marker", ["|", "|-", "|+", ">", ">-", ">+"])
def test_sec05_yaml_block_scalar_secret_content_is_redacted(marker: str) -> None:
    raw = (
        f"password: {marker}\n  yaml-block-canary\n  second secret line\ncommand: sas -sysin x.sas"
    )

    sanitized = sanitize_discovery_value(raw)
    serialized = json.dumps(
        Workload(workload_id="WL-YAML-BLOCK", name="w", metadata={"config": raw}).to_dict()
    )

    assert "yaml-block-canary" not in sanitized
    assert "second secret line" not in sanitized
    assert "yaml-block-canary" not in serialized
    assert "second secret line" not in serialized
    assert "command: sas -sysin x.sas" in sanitized
    assert REDACTED in sanitized


@pytest.mark.parametrize(
    "raw",
    [
        r'--authorization Digest username="reporter"\ --AUTH_LEAK_CANARY --host db.example',
        r"--auth Token prefix\;AUTH_LEAK_CANARY --host db.example",
    ],
)
def test_sec05_authentication_payload_respects_shell_escaping(raw: str) -> None:
    sanitized = sanitize_discovery_value(raw)

    assert "AUTH_LEAK_CANARY" not in sanitized
    assert "--host db.example" in sanitized
    assert REDACTED in sanitized


@pytest.mark.parametrize(
    "raw",
    [
        "CI_JOB_JWT=jwt-canary sas -sysin claims.sas",
        "SERVICE_JWT_TOKEN=jwt-token-canary sas -sysin claims.sas",
        "OIDC_ID_TOKEN=id-token-canary sas -sysin claims.sas",
    ],
)
def test_sec05_jwt_style_environment_credentials_are_redacted(raw: str) -> None:
    sanitized = sanitize_discovery_value(raw)
    serialized = json.dumps(
        Workload(workload_id="WL-JWT", name="w", metadata={"command": raw}).to_dict()
    )

    assert "canary" not in sanitized
    assert "canary" not in serialized
    assert REDACTED in sanitized


@pytest.mark.parametrize(
    ("raw", "retained"),
    [
        (
            "curl --user=reporter:curl-user-eq-canary https://db.example",
            "--user=reporter:<redacted>",
        ),
        (
            "curl --user reporter:curl-user-space-canary https://db.example",
            "--user reporter:<redacted>",
        ),
        (
            "curl -ureporter:curl-user-compact-canary https://db.example",
            "-ureporter:<redacted>",
        ),
        (
            "curl -u reporter:curl-user-short-canary https://db.example",
            "-u reporter:<redacted>",
        ),
        (
            "curl --proxy-user=reporter:curl-proxy-eq-canary https://db.example",
            "--proxy-user=reporter:<redacted>",
        ),
        (
            "curl --proxy-user reporter:curl-proxy-space-canary https://db.example",
            "--proxy-user reporter:<redacted>",
        ),
    ],
)
def test_sec05_common_userinfo_command_forms_are_redacted(raw: str, retained: str) -> None:
    sanitized = sanitize_discovery_value(raw)
    serialized = json.dumps(
        Workload(workload_id="WL-USERINFO", name="w", metadata={"command": raw}).to_dict()
    )

    assert "canary" not in sanitized
    assert "canary" not in serialized
    assert retained in sanitized
    assert "https://db.example" in sanitized


def test_sec05_yaml_block_scalar_explicit_indent_indicator_is_honored() -> None:
    raw = "password: |2-\n    first-secret-canary\n  second-secret-canary\nnext: safe-value"

    sanitized = sanitize_discovery_value(raw)
    serialized = json.dumps(
        Workload(workload_id="WL-YAML-INDENT", name="w", metadata={"config": raw}).to_dict()
    )

    assert "first-secret-canary" not in sanitized
    assert "second-secret-canary" not in sanitized
    assert "first-secret-canary" not in serialized
    assert "second-secret-canary" not in serialized
    assert "next: safe-value" in sanitized
    assert REDACTED in sanitized


def test_sec05_workload_identity_is_secret_independent() -> None:
    first = WorkloadBuilder(name="DB_PASSWORD=alpha-canary sas -sysin claims.sas")
    second = WorkloadBuilder(name="DB_PASSWORD=beta-canary sas -sysin claims.sas")

    first_workload = first.build()
    second_workload = second.build()

    assert first_workload.workload_id == second_workload.workload_id
    assert first_workload.name == second_workload.name
    assert first_workload.name == "DB_PASSWORD=<redacted> sas -sysin claims.sas"


def test_sec05_quoted_auth_payload_consumes_option_like_content() -> None:
    raw = '--auth "Digest username=reporter --host auth-quoted-canary" --verbose'

    sanitized = sanitize_discovery_value(raw)
    serialized = json.dumps(
        Workload(workload_id="WL-AUTH-QUOTED", name="w", metadata={"command": raw}).to_dict()
    )

    assert "auth-quoted-canary" not in sanitized
    assert "auth-quoted-canary" not in serialized
    assert sanitized == '--auth "Digest <redacted>" --verbose'
