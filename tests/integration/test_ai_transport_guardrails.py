from pathlib import Path

from tests.unit.ai_transport_test_support import make_transport_case


def test_transport_fixture_contains_no_live_humana_endpoint_or_credential(tmp_path: Path) -> None:
    case = make_transport_case(tmp_path)
    assert "humana" not in case["endpoint_path"].read_text().lower()
    assert "credential" not in case["endpoint_path"].read_text().lower().replace(
        "credential-resolution", ""
    )
