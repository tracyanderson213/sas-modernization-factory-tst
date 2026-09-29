# DBX-01 bounded remote-execution foundation

DBX-01 now composes current CV-04 deterministic-package evidence, DBPKG-01 target-plan evidence,
signed DBX-02 authentication evidence and fully replayed DBX-03 compute admission. Every upstream
identity and digest is bound to the same client, deployment, environment, workload, run and attempt.
Changed source, generated package, target, authentication or compute evidence fails closed.

The canonical result remains `blocked_external_authority`. Remote submission is disabled until a
separate live-execution decision, target-specific submission details and Unity Catalog read-back
authority exist. The result distinguishes generated from submitted, executed, validated,
parity-passed and human-assisted; only `generated` may be true in this increment.

An internally evaluated synthetic scenario contract exercises deterministic idempotency keys,
polling, terminal success and failure mapping, lost submit responses, bounded timeout cancellation
and unknown outcomes. It accepts no caller-provided transport or network-capable callback. Its
evidence class is always `synthetic_contract`; it never authorizes or claims a live submission.
Public verification reacquires and fully replays the current CV-04, DBPKG-01, DBX-02 and DBX-03
inputs; a self-consistent caller-authored result is not authority.

This increment does not contact Databricks, Unity Catalog, Azure, Humana or a source system. It does
not allocate compute, submit or cancel a real task, validate output, prove parity, establish
readiness, accept an exception, authorize promotion or complete migration. DBX-01 AC05 remains
externally blocked until separately authorized attributable remote run/task evidence exists.

Run `make dbx01-confidence` for deterministic contract evidence.
