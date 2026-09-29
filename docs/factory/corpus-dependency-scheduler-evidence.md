# Corpus Dependency and Scheduler Evidence

CORPUS-06 adds a typed expectation contract for dependency and orchestration evidence.

The contract separates a **declared workload relationship** from an **expected discovery
observation**. This matters because a corpus must be able to say that a dependency is known to
exist while its target remains unresolved. SMF must not fabricate a target merely to complete a
graph.

Each dependency expectation records a stable ID, source artifact, relationship kind, resolution
state, evidence method, and either a declared target artifact or the unresolved reference that was
observed. Resolved expectations must point to declared corpus artifacts. Unresolved expectations
must not carry a concrete target.

The controlled foundation fixture covers SAS includes, shell-to-SAS runtime launch, scheduler
launch, producer/consumer data relationships, an environment-driven dynamic SAS target, and an
AutoSys predecessor that is referenced but not locally defined.

This fixture is deterministic infrastructure, not representative enterprise evidence. CORPUS-07
uses the same contract against independently authored untouched public workloads.
