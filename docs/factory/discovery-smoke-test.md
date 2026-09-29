# Discovery end-to-end smoke test

The repository includes a synthetic multi-artifact SAS estate under
`tests/fixtures/e2e/sample-sas-estate`. It is intended to prove that the discovery
pipeline can connect independently discovered facts into one canonical workload graph.

Run:

```bash
./scripts/smoke-test-discovery.sh
```

The command runs the real `smf discover` CLI, writes `out/smoke/discovery.json`, and
validates expected inventory, data endpoint characterization, cross-program lineage,
shell launch relationships, AutoSys JIL relationships, cron scheduling, secret
redaction, and unresolved dependency handling.

This is a Level 3 synthetic estate test. It does not prove SAS runtime execution,
Databricks execution, SAS-to-Databricks output parity, enterprise scheduler API
connectivity, or Humana workload compatibility.
