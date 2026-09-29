import json
from pathlib import Path

from smf.discovery.base import DiscoveryRequest
from smf.discovery.filesystem import FilesystemDiscoveryProvider
from smf.discovery.models import DiscoveryResult
from smf.workload.models import (
    ArtifactKind,
    DependencyDomain,
    DependencyResolutionReason,
    EvidenceMethod,
    RelationshipKind,
)


def _discover(tmp_path: Path):
    return FilesystemDiscoveryProvider().discover(
        DiscoveryRequest(source=tmp_path, namespace="test")
    )[0]


def test_shell_wrapper_triggers_sas_program(tmp_path: Path) -> None:
    (tmp_path / "jobs").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "jobs" / "monthly.sas").write_text(
        "data work.out; set work.in; run;\n",
        encoding="utf-8",
    )
    (tmp_path / "scripts" / "run_monthly.sh").write_text(
        "#!/bin/bash\nsas -sysin jobs/monthly.sas\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    artifacts = {item.name: item for item in workload.artifacts}
    wrapper = artifacts["run_monthly.sh"]
    program = artifacts["monthly.sas"]

    triggers = [
        item
        for item in workload.relationships
        if item.source_id == wrapper.artifact_id
        and item.kind is RelationshipKind.TRIGGERS
        and item.target_id == program.artifact_id
    ]

    assert len(triggers) == 1
    assert triggers[0].evidence[0].method is EvidenceMethod.STATIC_ANALYSIS
    assert wrapper.metadata["runtime_invocations"][0]["resolution"] == "resolved"


def test_explicit_relative_launch_remains_unresolved_without_cwd_evidence(
    tmp_path: Path,
) -> None:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "target.sas").write_text("data root; run;\n", encoding="utf-8")
    (tmp_path / "scripts" / "target.sas").write_text(
        "data nested; run;\n",
        encoding="utf-8",
    )
    wrapper_path = tmp_path / "scripts" / "run.sh"
    wrapper_path.write_text("sas -sysin ./target.sas\n", encoding="utf-8")

    workload = _discover(tmp_path)
    wrapper = next(item for item in workload.artifacts if item.logical_path == "scripts/run.sh")

    assert wrapper.metadata["runtime_invocations"][0]["target"] == "./target.sas"
    assert wrapper.metadata["runtime_invocations"][0]["resolution"] == "unresolved"
    assert not any(
        item.source_id == wrapper.artifact_id and item.kind is RelationshipKind.TRIGGERS
        for item in workload.relationships
    )
    assert workload.dependency_graph is not None
    unresolved = next(
        item
        for item in workload.dependency_graph.unresolved
        if item.source_id == wrapper.artifact_id and item.reference == "./target.sas"
    )
    assert unresolved.domain is DependencyDomain.RUNTIME_LAUNCH
    assert unresolved.reason is DependencyResolutionReason.MISSING


def test_parent_relative_launch_remains_unresolved_without_cwd_evidence(
    tmp_path: Path,
) -> None:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "target.sas").write_text("data root; run;\n", encoding="utf-8")
    wrapper_path = tmp_path / "scripts" / "run.sh"
    wrapper_path.write_text("sas -sysin ../target.sas\n", encoding="utf-8")

    workload = _discover(tmp_path)
    wrapper = next(item for item in workload.artifacts if item.logical_path == "scripts/run.sh")

    assert wrapper.metadata["runtime_invocations"][0]["target"] == "../target.sas"
    assert wrapper.metadata["runtime_invocations"][0]["resolution"] == "unresolved"
    assert not any(
        item.source_id == wrapper.artifact_id and item.kind is RelationshipKind.TRIGGERS
        for item in workload.relationships
    )
    assert workload.dependency_graph is not None
    unresolved = next(
        item
        for item in workload.dependency_graph.unresolved
        if item.source_id == wrapper.artifact_id and item.reference == "../target.sas"
    )
    assert unresolved.domain is DependencyDomain.RUNTIME_LAUNCH
    assert unresolved.reason is DependencyResolutionReason.MISSING


def test_repeated_resolved_launches_merge_all_evidence(tmp_path: Path) -> None:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "target.sas").write_text("data nested; run;\n", encoding="utf-8")
    (tmp_path / "scripts" / "run.sh").write_text(
        "sas -sysin scripts/target.sas\nsas -sysin scripts/target.sas\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    wrapper = next(item for item in workload.artifacts if item.logical_path == "scripts/run.sh")
    target = next(item for item in workload.artifacts if item.logical_path == "scripts/target.sas")
    trigger = next(
        item
        for item in workload.relationships
        if item.source_id == wrapper.artifact_id
        and item.kind is RelationshipKind.TRIGGERS
        and item.target_id == target.artifact_id
    )

    assert {item.locator for item in trigger.evidence} == {"line 1", "line 2"}
    assert workload.dependency_graph is not None
    graph_edge = next(
        item
        for item in workload.dependency_graph.edges
        if item.source_id == wrapper.artifact_id
        and item.kind is RelationshipKind.TRIGGERS
        and item.target_id == target.artifact_id
    )
    assert {item.locator for item in graph_edge.evidence} == {"line 1", "line 2"}


def test_scheduler_relative_launches_remain_unresolved_without_cwd_evidence(
    tmp_path: Path,
) -> None:
    (tmp_path / "scheduler").mkdir()
    (tmp_path / "scheduler" / "run.sh").write_text("exit 0\n", encoding="utf-8")
    (tmp_path / "scheduler" / "schedule.jil").write_text(
        "insert_job: RELATIVE_JOB job_type: c\ncommand: ./run.sh\n",
        encoding="utf-8",
    )
    (tmp_path / "scheduler" / "crontab").write_text(
        "0 2 * * * ./run.sh\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    assert workload.dependency_graph is not None
    scheduler_jobs = [
        item
        for item in workload.artifacts
        if item.kind is ArtifactKind.SCHEDULER_JOB
        and item.metadata.get("scheduler_format") in {"autosys_jil", "cron"}
    ]

    assert len(scheduler_jobs) == 2
    assert all(
        item.metadata["runtime_invocations"][0]["resolution"] == "unresolved"
        for item in scheduler_jobs
    )
    assert not any(
        relationship.source_id in {item.artifact_id for item in scheduler_jobs}
        and relationship.kind is RelationshipKind.TRIGGERS
        for relationship in workload.relationships
    )
    assert {
        item.source_id
        for item in workload.dependency_graph.unresolved
        if item.reference == "./run.sh" and item.domain is DependencyDomain.RUNTIME_LAUNCH
    } == {item.artifact_id for item in scheduler_jobs}


def test_dynamic_shell_target_remains_unresolved(tmp_path: Path) -> None:
    script = tmp_path / "run_dynamic.sh"
    script.write_text('sas -sysin "$PROGRAM"\n', encoding="utf-8")

    workload = _discover(tmp_path)
    wrapper = next(item for item in workload.artifacts if item.name == script.name)

    assert wrapper.metadata["runtime_invocations"][0]["resolution"] == "dynamic"
    assert not any(
        item.kind is RelationshipKind.TRIGGERS and item.source_id == wrapper.artifact_id
        for item in workload.relationships
    )


def test_runtime_launch_evidence_does_not_persist_credential_arguments(tmp_path: Path) -> None:
    script = tmp_path / "run_dynamic.sh"
    script.write_text(
        'sas -sysin "$PROGRAM" -set password hunter2\n',
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    payload = json.dumps(workload.to_dict())
    wrapper = next(item for item in workload.artifacts if item.name == script.name)
    assert workload.dependency_graph is not None
    unresolved = next(
        item
        for item in workload.dependency_graph.unresolved
        if item.source_id == wrapper.artifact_id and item.domain is DependencyDomain.RUNTIME_LAUNCH
    )

    assert "hunter2" not in payload
    assert wrapper.metadata["runtime_invocations"][0]["observed_value"] == "$PROGRAM"
    assert unresolved.evidence[0].observed_value == "$PROGRAM"


def test_autosys_jil_creates_ordering_and_launch_dependencies(tmp_path: Path) -> None:
    (tmp_path / "jobs").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "jobs" / "claims.sas").write_text("data work.x; run;\n", encoding="utf-8")
    (tmp_path / "scripts" / "run_claims.sh").write_text(
        "sas -sysin jobs/claims.sas\n",
        encoding="utf-8",
    )
    (tmp_path / "schedule.jil").write_text(
        """
insert_job: LOAD_SOURCE job_type: c
command: /opt/batch/load_source.sh
machine: batch01

insert_job: RUN_CLAIMS job_type: c
command: scripts/run_claims.sh
condition: s(LOAD_SOURCE)
start_times: "03:00"
days_of_week: all
""".strip()
        + "\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    assert workload.dependency_graph is not None
    scheduler_jobs = {
        item.name: item
        for item in workload.artifacts
        if item.kind is ArtifactKind.SCHEDULER_JOB and "#" in (item.logical_path or "")
    }
    run_claims = scheduler_jobs["RUN_CLAIMS"]
    load_source = scheduler_jobs["LOAD_SOURCE"]
    wrapper = next(item for item in workload.artifacts if item.name == "run_claims.sh")

    assert run_claims.metadata["start_times"] == '"03:00"'
    assert run_claims.metadata["days_of_week"] == "all"

    assert any(
        item.source_id == run_claims.artifact_id
        and item.kind is RelationshipKind.DEPENDS_ON
        and item.target_id == load_source.artifact_id
        for item in workload.relationships
    )
    unresolved_launch = next(
        item
        for item in workload.dependency_graph.unresolved
        if item.source_id == load_source.artifact_id
        and item.reference == "/opt/batch/load_source.sh"
    )
    assert unresolved_launch.domain is DependencyDomain.RUNTIME_LAUNCH
    assert unresolved_launch.reason is DependencyResolutionReason.MISSING
    assert unresolved_launch.evidence[0].method is EvidenceMethod.SCHEDULER_METADATA
    assert any(
        item.source_id == load_source.artifact_id
        and item.kind is RelationshipKind.PRECEDES
        and item.target_id == run_claims.artifact_id
        for item in workload.relationships
    )
    assert any(
        item.source_id == run_claims.artifact_id
        and item.kind is RelationshipKind.TRIGGERS
        and item.target_id == wrapper.artifact_id
        and item.evidence[0].method is EvidenceMethod.SCHEDULER_METADATA
        for item in workload.relationships
    )


def test_autosys_external_condition_is_preserved_as_referenced_job(tmp_path: Path) -> None:
    (tmp_path / "schedule.jil").write_text(
        "insert_job: LOCAL_JOB job_type: c\ncommand: /bin/true\ncondition: s(EXTERNAL_UPSTREAM)\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    external = next(item for item in workload.artifacts if item.name == "EXTERNAL_UPSTREAM")
    local = next(item for item in workload.artifacts if item.name == "LOCAL_JOB")

    assert external.metadata["definition_status"] == "referenced_only"
    assert any(
        item.source_id == local.artifact_id
        and item.kind is RelationshipKind.DEPENDS_ON
        and item.target_id == external.artifact_id
        for item in workload.relationships
    )


def test_cron_entry_creates_scheduler_job_and_trigger(tmp_path: Path) -> None:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "nightly.sh").write_text("echo nightly\n", encoding="utf-8")
    (tmp_path / "crontab").write_text(
        "0 2 * * * scripts/nightly.sh\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    nightly = next(item for item in workload.artifacts if item.name == "nightly.sh")
    cron_jobs = [
        item
        for item in workload.artifacts
        if item.kind is ArtifactKind.SCHEDULER_JOB
        and item.metadata.get("scheduler_format") == "cron"
    ]

    assert len(cron_jobs) == 1
    assert cron_jobs[0].metadata["schedule"] == "0 2 * * *"
    assert any(
        item.source_id == cron_jobs[0].artifact_id
        and item.kind is RelationshipKind.TRIGGERS
        and item.target_id == nightly.artifact_id
        for item in workload.relationships
    )


def test_cron_unresolved_launch_is_preserved_in_graph(tmp_path: Path) -> None:
    (tmp_path / "crontab").write_text(
        "0 2 * * * /opt/enterprise/load_source.sh\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    assert workload.dependency_graph is not None
    cron_job = next(
        item
        for item in workload.artifacts
        if item.kind is ArtifactKind.SCHEDULER_JOB
        and item.metadata.get("scheduler_format") == "cron"
    )
    unresolved = next(
        item
        for item in workload.dependency_graph.unresolved
        if item.source_id == cron_job.artifact_id
    )
    assert unresolved.reference == "/opt/enterprise/load_source.sh"
    assert unresolved.domain is DependencyDomain.RUNTIME_LAUNCH
    assert unresolved.reason is DependencyResolutionReason.MISSING
    assert unresolved.evidence[0].method is EvidenceMethod.SCHEDULER_METADATA


def test_scheduler_and_runtime_credentials_never_enter_durable_graph(tmp_path: Path) -> None:
    canaries = {
        "jil-canary",
        "jil-quoted-canary",
        "cron-canary",
        "shell-canary",
        "escaped-shell-canary",
        "uri-canary",
        "cron-header-canary",
        "scheduler-digest-canary",
        "oracle-canary",
    }
    (tmp_path / "jobs").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "jobs" / "claims.sas").write_text("data work.x; run;\n", encoding="utf-8")
    (tmp_path / "scripts" / "run_claims.sh").write_text(
        "DB_PASSWORD=shell-canary "
        r"SESSION_TOKEN=prefix\ escaped-shell-canary sas -sysin jobs/claims.sas "
        "--endpoint postgres://reporter:uri-canary@db.example/claims\n",
        encoding="utf-8",
    )
    (tmp_path / "schedule.jil").write_text(
        "insert_job: RUN_CLAIMS job_type: c\n"
        'command: env "DB_PASSWORD=prefix jil-quoted-canary" '
        "AUTH_TOKEN=jil-canary scripts/run_claims.sh\n"
        'start_times: "03:00"\n',
        encoding="utf-8",
    )
    (tmp_path / "crontab").write_text(
        "0 2 * * * PROD_API_KEY=cron-canary "
        "scripts/run_claims.sh -H 'Authorization: Token cron-header-canary' "
        "--dsn jdbc:oracle:thin:reporter/oracle-canary@db.example:1521/claims\n"
        "15 2 * * * scripts/run_claims.sh "
        '-H \'Authorization: Digest username="reporter", realm="db", '
        'response="scheduler-digest-canary"\'\n',
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    serialized = json.dumps(workload.to_dict())
    result_serialized = json.dumps(
        DiscoveryResult(
            provider="filesystem",
            source=str(tmp_path),
            workloads=(workload,),
        ).to_dict()
    )

    assert not any(canary in serialized for canary in canaries)
    assert not any(canary in result_serialized for canary in canaries)
    assert "scripts/run_claims.sh" in serialized
    assert "jobs/claims.sas" in serialized
    assert "db.example" in serialized
    assert "Authorization: Token <redacted>" in serialized
    assert "Authorization: Digest <redacted>" in serialized
    assert "jdbc:oracle:thin:reporter/<redacted>@db.example:1521/claims" in serialized
    assert any(item.kind is RelationshipKind.TRIGGERS for item in workload.relationships)
    # Discovery sanitizes copied canonical evidence, never the acquired bytes.
    assert "jil-canary" in (tmp_path / "schedule.jil").read_text()
    assert "shell-canary" in (tmp_path / "scripts" / "run_claims.sh").read_text()
    assert "escaped-shell-canary" in (tmp_path / "scripts" / "run_claims.sh").read_text()
    assert "scheduler-digest-canary" in (tmp_path / "crontab").read_text()


def test_cron_and_jil_commands_use_canonical_secret_sanitization(tmp_path: Path) -> None:
    canaries = {
        "cron-password-canary",
        "cron-pass-canary",
        "cron-url-canary",
        "jil-password-canary",
        "jil-pass-canary",
        "jil-url-canary",
    }
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "run.sh").write_text("exit 0\n", encoding="utf-8")
    (tmp_path / "crontab").write_text(
        "0 1 * * * DB_PASSWORD=cron-password-canary scripts/run.sh "
        "-set pass cron-pass-canary "
        "postgres://batch:cron-url-canary@db.example/jobs\n",
        encoding="utf-8",
    )
    (tmp_path / "schedule.jil").write_text(
        "insert_job: SECRET_JOB job_type: c\n"
        "command: DB_PASSWORD=jil-password-canary scripts/run.sh "
        "-set pass jil-pass-canary "
        "postgres://batch:jil-url-canary@db.example/jobs\n",
        encoding="utf-8",
    )

    workload = _discover(tmp_path)
    serialized = json.dumps(workload.to_dict())

    assert not any(canary in serialized for canary in canaries)
    assert serialized.count("DB_PASSWORD=<redacted>") >= 2
    assert serialized.count("-set pass <redacted>") >= 2
    assert serialized.count("postgres://batch:<redacted>@db.example/jobs") >= 2
