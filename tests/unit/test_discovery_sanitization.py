import json
from collections import OrderedDict

import pytest

from smf.workload.sanitization import REDACTED, sanitize_discovery_value


@pytest.mark.parametrize(
    ("raw", "secret", "retained"),
    [
        ("password=hunter2", "hunter2", "password="),
        (r"DB_PASSWORD=prefix\ shell-canary sas -sysin job.sas", "shell-canary", "job.sas"),
        (
            'env "DB_PASSWORD=prefix reviewer-canary" sas -sysin job.sas',
            "prefix reviewer-canary",
            "sas -sysin job.sas",
        ),
        (r"--api-key=prefix\ key-canary --host db.example", "key-canary", "db.example"),
        ("pass='two words'", "two words", "pass="),
        ("PWD=mixedCase", "mixedCase", "PWD="),
        ("export DB_PASSWORD=db-canary", "db-canary", "DB_PASSWORD="),
        ("PROD_API_KEY=api-canary", "api-canary", "PROD_API_KEY="),
        ("SERVICE_AUTH_TOKEN=token-canary", "token-canary", "SERVICE_AUTH_TOKEN="),
        ("AWS_SECRET_ACCESS_KEY=aws-canary", "aws-canary", "AWS_SECRET_ACCESS_KEY="),
        ("GITHUB_PAT=github-canary", "github-canary", "GITHUB_PAT="),
        ("SECRET_KEY_BASE=rails-canary", "rails-canary", "SECRET_KEY_BASE="),
        ("--client-secret cli-canary --host db.example", "cli-canary", "db.example"),
        ("--authentication=auth-canary", "auth-canary", "--authentication="),
        ("AUTH=environment-auth-canary", "environment-auth-canary", "AUTH="),
        ("--authorization Bearer option-canary", "option-canary", "--authorization"),
        (
            '--authorization "Bearer quoted-option-canary" --host db.example',
            "quoted-option-canary",
            "db.example",
        ),
        ("curl -u reporter:curl-canary https://db.example", "curl-canary", "reporter:"),
        ("Authorization: Bearer bearer-canary", "bearer-canary", "Bearer"),
        (
            r"--authorization Bearer prefix\ escaped-bearer-canary --verbose",
            "escaped-bearer-canary",
            "--verbose",
        ),
        ("authorization: Basic basic-canary", "basic-canary", "Basic"),
        ("Authorization: Token token-scheme-canary", "token-scheme-canary", "Token"),
        ("Authorization: ApiKey api-scheme-canary", "api-scheme-canary", "ApiKey"),
        ("Authentication: Digest digest-canary", "digest-canary", "Digest"),
        (
            'curl -H \'Authorization: Digest username="reporter", realm="db", '
            'response="digest-response-canary"\' https://db.example',
            "digest-response-canary",
            "Authorization: Digest <redacted>",
        ),
        (
            '{"Authorization": "Bearer json-auth-canary"}',
            "json-auth-canary",
            '"Authorization": "Bearer',
        ),
        (
            "authentication: 'Basic yaml-auth-canary'",
            "yaml-auth-canary",
            "authentication: 'Basic",
        ),
        (
            "postgres://reporter:uri-canary@db.example/claims?ssl=true",
            "uri-canary",
            "postgres://reporter:",
        ),
        (
            "redis://:redis-canary@cache.example/0",
            "redis-canary",
            "redis://:<redacted>@cache.example/0",
        ),
        (
            "ssh reporter:userinfo-canary@db.example",
            "userinfo-canary",
            "reporter:<redacted>@db.example",
        ),
        (
            "ssh 'reporter:quoted-userinfo-canary@db.example'",
            "quoted-userinfo-canary",
            "reporter:<redacted>@db.example",
        ),
        (
            "Driver=ODBC;Server=db.example;Database=claims;Password=odbc-canary;",
            "odbc-canary",
            "Database=claims",
        ),
        # Assert on the trailing token: the former sanitizer redacted only
        # "two" and leaked "words" after the whitespace.
        ("Password=two words;", "words", "Password=<redacted>;"),
        (
            "Server=db.example;Password=two words;Database=claims",
            "words",
            "Database=claims",
        ),
        (
            "Server=db.example;Password=unterminated two words",
            "unterminated two words",
            "Server=db.example;Password=<redacted>",
        ),
        (
            "Server=db; Password=prefix reviewer-canary",
            "prefix reviewer-canary",
            "Server=db; Password=<redacted>",
        ),
        (
            "jdbc:sqlserver://db;user=reporter;password=jdbc-canary;encrypt=true",
            "jdbc-canary",
            "encrypt=true",
        ),
        (
            "jdbc:oracle:thin:reporter/oracle-canary@db.example:1521/claims",
            "oracle-canary",
            "jdbc:oracle:thin:reporter/",
        ),
        (
            "DefaultEndpointsProtocol=https;AccountKey=azure-canary;EndpointSuffix=core.windows.net",
            "azure-canary",
            "EndpointSuffix=core.windows.net",
        ),
        (
            "https://db/path?api_key=query-canary&schema=public",
            "query-canary",
            "schema=public",
        ),
        (
            "Endpoint=sb://bus.example;SharedAccessKeyName=reader;"
            "SharedAccessKey=shared-access-canary",
            "shared-access-canary",
            "SharedAccessKeyName=reader",
        ),
        (
            "https://storage.example/blob?sv=2024-11-04&sig=sas-signature-canary&sp=r",
            "sas-signature-canary",
            "sp=r",
        ),
        ("X-API-Key: header-key-canary", "header-key-canary", "X-API-Key:"),
        ('{"password": "json-password-canary"}', "json-password-canary", '"password":'),
        (
            '{"githubToken":"github-token-raw-canary"}',
            "github-token-raw-canary",
            '"githubToken":',
        ),
        ("serviceAPIToken: yaml-token-canary", "yaml-token-canary", "serviceAPIToken:"),
        ("--githubToken=command-token-canary", "command-token-canary", "--githubToken="),
        ("password: yaml-password-canary", "yaml-password-canary", "password:"),
        ("PWD={odbc;brace-canary}", "brace-canary", "PWD="),
        ("PASSWORD=comma,secret-canary", "comma,secret-canary", "PASSWORD="),
        ("SharedAccessSignature=azure-sas-canary", "azure-sas-canary", "="),
    ],
)
def test_sanitizes_credential_forms(raw: str, secret: str, retained: str) -> None:
    sanitized = sanitize_discovery_value(raw)

    assert secret not in sanitized
    assert REDACTED in sanitized
    assert retained in sanitized


def test_recurses_without_mutating_nested_metadata_and_is_idempotent() -> None:
    raw = {
        "host": "db.example",
        "DB_PASSWORD": "dict-canary",
        "environment": [
            {"name": "ACCESS_TOKEN", "value": "pair-canary", "scope": "read"},
            "SHARED_KEY=list-canary",
        ],
        "nested": ({"credentials": "credential-canary"},),
    }

    sanitized = sanitize_discovery_value(raw)

    assert "dict-canary" in json.dumps(raw)
    assert not any(
        secret in json.dumps(sanitized)
        for secret in ("dict-canary", "pair-canary", "list-canary", "credential-canary")
    )
    assert sanitized["host"] == "db.example"
    assert sanitized["environment"][0]["name"] == "ACCESS_TOKEN"
    assert sanitized["environment"][0]["scope"] == "read"
    assert isinstance(sanitized["nested"], tuple)
    assert sanitize_discovery_value(sanitized) == sanitized


def test_sanitizes_camel_case_secret_fields_without_redacting_safe_counters() -> None:
    raw = {
        "githubToken": "github-token-canary",
        "sessionToken": "session-token-canary",
        "bearerToken": "bearer-token-canary",
        "serviceAPIToken": "api-token-canary",
        "passwordValue": "password-value-canary",
        "password_value": "snake-password-value-canary",
        "tokenCount": 17,
        "accessTokenCount": 3,
    }

    sanitized = sanitize_discovery_value(raw)
    serialized = json.dumps(sanitized)

    assert not any(
        canary in serialized
        for canary in (
            "github-token-canary",
            "session-token-canary",
            "bearer-token-canary",
            "api-token-canary",
            "password-value-canary",
            "snake-password-value-canary",
        )
    )
    assert sanitized["tokenCount"] == 17
    assert sanitized["accessTokenCount"] == 3


@pytest.mark.parametrize(
    "raw",
    [
        {"Name": "DB_PASSWORD", "Value": "UPPER-PAIR-CANARY"},
        {"key": "API_KEY", "value": "KEY-PAIR-CANARY"},
        {"variable": "SERVICE_AUTH_TOKEN", "val": "VARIABLE-PAIR-CANARY"},
        {"name": "GITHUB_PAT", "value": "GITHUB-PAT-PAIR-CANARY"},
        {"name": "SECRET_KEY_BASE", "value": "SECRET-KEY-BASE-PAIR-CANARY"},
    ],
)
def test_sanitizes_case_insensitive_environment_name_value_records(
    raw: dict[str, str],
) -> None:
    serialized = json.dumps(sanitize_discovery_value(raw))

    assert "PAIR-CANARY" not in serialized
    assert REDACTED in serialized


@pytest.mark.parametrize("pair_type", [list, tuple])
def test_sanitizes_environment_sequence_pairs(pair_type: type[list] | type[tuple]) -> None:
    pair = pair_type(("DB_PASSWORD", "sequence-pair-canary"))
    raw = {"environment": [pair], "host": "db.example"}

    sanitized = sanitize_discovery_value(raw)
    serialized = json.dumps(sanitized)

    assert "sequence-pair-canary" not in serialized
    assert "DB_PASSWORD" in serialized
    assert sanitized["host"] == "db.example"


@pytest.mark.parametrize(
    "value",
    [
        {"token_count": 17, "username": "reporter", "dsn": "warehouse"},
        {"compat": "supported"},
        "--token-count 17 --username reporter --schema public",
        "host=db.example;database=claims;user=reporter",
    ],
)
def test_preserves_safe_identifiers_and_avoids_false_positives(value: object) -> None:
    assert sanitize_discovery_value(value) == value


def test_fails_closed_for_opaque_metadata_values() -> None:
    with pytest.raises(TypeError, match="unsupported discovery metadata value type"):
        sanitize_discovery_value(object())


def test_preserves_ordered_mapping_shape() -> None:
    raw = OrderedDict((("host", "db.example"), ("password", "ordered-canary")))

    sanitized = sanitize_discovery_value(raw)

    assert isinstance(sanitized, OrderedDict)
    assert list(sanitized) == ["host", "password"]
    assert sanitized["password"] == REDACTED


def test_sanitizes_secret_material_embedded_in_mapping_keys() -> None:
    sanitized = sanitize_discovery_value({"password=key-canary": "observed"})

    assert "key-canary" not in json.dumps(sanitized)
    assert sanitized == {"password=<redacted>": "observed"}
