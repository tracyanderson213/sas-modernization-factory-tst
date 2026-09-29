from smf.workload.identity import stable_id


def test_stable_id_is_independent_of_mapping_order() -> None:
    first = stable_id("WL", {"name": "claims", "namespace": "humana"})
    second = stable_id("WL", {"namespace": "humana", "name": "claims"})

    assert first == second


def test_stable_id_changes_when_logical_identity_changes() -> None:
    first = stable_id("WL", {"name": "claims", "namespace": "humana"})
    second = stable_id("WL", {"name": "members", "namespace": "humana"})

    assert first != second
