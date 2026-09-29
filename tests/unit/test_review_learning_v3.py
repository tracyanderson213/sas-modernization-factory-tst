from pathlib import Path

from smf.engineering_agent.review_feedback import ReviewFinding, parse_review
from smf.engineering_agent.review_learning import classify_finding


def test_mutable_does_not_match_immutable() -> None:
    finding = ReviewFinding(
        "RF-1",
        "HIGH",
        "Baseline evidence is reconstructable",
        "Use an immutable retrievable baseline reference.",
    )
    assert classify_finding(Path.cwd(), finding) == "ASSERTION_NOT_EVIDENCE"


def test_trailing_summary_does_not_contaminate_final_finding() -> None:
    packet = parse_review(
        "FAIL\n\n"
        "1. **High - Baseline assertion is not reconstructable evidence**\n"
        "Expected a retrievable baseline artifact.\n\n"
        "2. **Medium - Interrupted manifest publication cannot recover its telemetry**\n"
        "Retry leaves telemetry absent.\n\n"
        "The malformed-enum, empty workload, and duplicate probes otherwise failed closed.\n"
        "Ruff and all tests passed.\n"
    )
    assert len(packet.findings) == 2
    assert "malformed-enum" not in packet.findings[-1].detail.lower()


def test_ready01_baseline_maps_to_assertion_not_evidence() -> None:
    finding = ReviewFinding(
        "RF-3",
        "HIGH",
        "A signed checksum assertion is accepted as a reconstructable baseline",
        "Require an immutable retrievable baseline artifact and verified digest.",
    )
    assert classify_finding(Path.cwd(), finding) == "ASSERTION_NOT_EVIDENCE"


def test_ready01_persistence_maps_to_recovery_pattern() -> None:
    finding = ReviewFinding(
        "RF-4",
        "MEDIUM",
        "Interrupted manifest publication cannot recover its telemetry",
        "Crash recovery must republish missing telemetry idempotently.",
    )
    assert classify_finding(Path.cwd(), finding) == "IDEMPOTENT_PERSISTENCE_RECOVERY"


def test_weak_single_detail_term_is_not_forced() -> None:
    finding = ReviewFinding(
        "RF-5",
        "MEDIUM",
        "Unrelated defect",
        "A generic boundary mention appears only in background.",
    )
    assert classify_finding(Path.cwd(), finding) is None


def test_ready01_unbound_findings_remain_unbound() -> None:
    root = Path.cwd()
    discovery = ReviewFinding(
        "RF-1",
        "HIGH",
        "Unauthenticated discovery scope can hide mandatory dependencies and evidence",
        "Evidence provenance is unbound from the complete workload.",
    )
    approval = ReviewFinding(
        "RF-2",
        "HIGH",
        "Human approval is replayable across unrelated runs and attempts",
        "The same approval is replayable across unrelated runs.",
    )
    assert classify_finding(root, discovery) == "UNBOUND_EVIDENCE"
    assert classify_finding(root, approval) == "UNBOUND_EVIDENCE"
