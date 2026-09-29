import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from smf.security import BindingStatus, load_security_configuration


def write_configuration(
    tmp_path: Path,
    *,
    status: str = "active",
    path: str = "apps/db",
    previous_version: str | None = None,
):
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """version: 1
policy_id: policy-1
identity:
  provider: microsoft-entra-id-active-directory
  workload_authentication_binding_status: active
secrets:
  provider: hashicorp-vault
  binding_status: active
""",
        encoding="utf-8",
    )
    binding = tmp_path / "binding.yaml"
    rotation = f"  previous_version: {previous_version}\n" if previous_version else ""
    binding.write_text(
        f"""schema_version: '1.0'
status: {status}
endpoint: https://vault.invalid
tls_profile_ref: tls-1
authority: security-authority
verification_keys:
  key-1: {base64.b64encode(public).decode()}
min_lease_seconds: 30
identity_bindings:
- binding_id: identity-1
  tenant: tenant-1
  issuer: https://issuer.invalid
  audience: vault
  authentication_flow: workload_identity_federation
secret_bindings:
- binding_id: secret-1
  namespace: humana
  auth_mount: jwt
  role: workload-reader
  engine: kv-v2
  path: '{path}'
  version: v1
{rotation}
""",
        encoding="utf-8",
    )
    return load_security_configuration(policy, binding), key, policy, binding


def test_strict_configuration_loads_opaque_unique_bindings(tmp_path: Path) -> None:
    config, _, _, _ = write_configuration(tmp_path)
    assert config.status is BindingStatus.ACTIVE
    assert set(config.identity_bindings) == {"identity-1"}
    assert set(config.secret_bindings) == {"secret-1"}


@pytest.mark.parametrize(
    "path",
    [
        "../escape",
        "%2e%2e/escape",
        "%252e%252e/escape",
        "/absolute",
        "apps/*",
        "apps/ｄｂ",
    ],
)
def test_configuration_rejects_boundary_escape(tmp_path: Path, path: str) -> None:
    with pytest.raises(ValueError, match="Unsafe secret path"):
        write_configuration(tmp_path, path=path)


def test_configuration_rejects_duplicate_keys_and_unknown_enums(tmp_path: Path) -> None:
    _, _, _, binding = write_configuration(tmp_path)
    binding.write_text(binding.read_text() + "status: active\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate"):
        load_security_configuration(tmp_path / "policy.yaml", binding)

    _, _, policy, binding = write_configuration(tmp_path)
    policy.write_text(
        policy.read_text().replace("binding_status: active", "binding_status: enabled")
    )
    with pytest.raises(ValueError, match="Unknown provider binding status"):
        load_security_configuration(policy, binding)


def test_configuration_rejects_case_ambiguous_binding_ids(tmp_path: Path) -> None:
    _, _, policy, binding = write_configuration(tmp_path)
    duplicate = binding.read_text().replace(
        "secret_bindings:\n",
        """- binding_id: IDENTITY-1
  tenant: tenant-1
  issuer: https://issuer.invalid
  audience: vault
  authentication_flow: workload_identity_federation
secret_bindings:
""",
    )
    binding.write_text(duplicate, encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate identity"):
        load_security_configuration(policy, binding)


def test_rotation_versions_must_be_distinct(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must differ"):
        write_configuration(tmp_path, previous_version="v1")

    config, _, _, _ = write_configuration(tmp_path, previous_version="v0")
    assert config.secret_bindings["secret-1"].previous_version == "v0"


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ("schema_version: '1.0'", "schema_version: '1.1'", "schema_version"),
        ("endpoint: https://vault.invalid", "endpoint: https://vault.invalid/secret", "origin"),
        ("issuer: https://issuer.invalid", "issuer: issuer.invalid", "HTTPS URL"),
        ("audience: vault", "audience: ''", "audience"),
    ],
)
def test_configuration_rejects_malformed_security_values(
    tmp_path: Path, old: str, new: str, message: str
) -> None:
    _, _, policy, binding = write_configuration(tmp_path)
    binding.write_text(binding.read_text().replace(old, new), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        load_security_configuration(policy, binding)
