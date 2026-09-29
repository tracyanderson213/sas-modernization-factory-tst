# TASK-11 row-count tolerance acceptance

TASK-11 supplies a versioned, offline row-count policy and immutable comparison evidence for later
composition by DP-02. It does not acquire source or target counts and does not duplicate the
distributed adapter. Counts remain observations bound to exact source and target snapshot identities.

| Criterion | Evidence | Result |
| --- | --- | --- |
| AC01 | Strict policy/result schemas and `test_ambiguous_or_noncanonical_policies_are_rejected` | Exact, absolute and relative policies are explicit, versioned and non-ambiguous. |
| AC02 | Boundary and zero-source tests in `test_row_count_tolerance.py` | Exact, inclusive absolute/relative limits, source denominator and zero-source rules are deterministic. |
| AC03 | Missing/negative/outside-boundary tests | Missing counts block; negative or boolean counts reject; outside tolerance fails without warning. |
| AC04 / HC01-05 | Snapshot-bound request, current-input replay, immutable publication, mutation, retry, symlink and isolation tests | Offline synthetic contract mechanics pass; no live customer comparison or parity claim exists. |

Passing this check means only that the supplied source/target counts satisfy the selected policy.
`data_parity_passed`, `certified`, `human_approved`, and `humana_validated` remain false. Humana
snapshot acquisition, approved tolerance selection, named ownership, distributed DP-02 execution,
cell/aggregate/semantic parity, Databricks execution, readiness, and migration completion are outside
this increment and remain unproven.
