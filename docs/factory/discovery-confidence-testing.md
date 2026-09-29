# Discovery Confidence Testing

Discovery is tested as a set of confidence gates rather than treating a pytest count as workload proof.

```text
                 +-----------------------+
                 | Unit + integration    |
                 +-----------+-----------+
                             |
                             v
                 +-----------------------+
                 | Gate A: controlled E2E|
                 | known expected graph  |
                 +-----------+-----------+
                             |
                             v
                 +-----------------------+
                 | Gate B: adversarial   |
                 | try to break discovery|
                 +-----------+-----------+
                             |
                             v
                 +-----------------------+
                 | Gate C: public corpus |
                 | parser-blind SAS input|
                 +-----------+-----------+
                             |
                             v
                    stronger real-runtime
                    evidence is still future
```

Run all three discovery gates with:

```bash
./scripts/test-discovery-confidence.sh
```

## Gate A: controlled acceptance

The synthetic multi-artifact estate under `tests/fixtures/e2e/sample-sas-estate` has a known topology. The test verifies that independently discovered SAS, data, lineage, shell, AutoSys, and cron facts connect into the expected canonical graph.

The standalone smoke command remains available:

```bash
./scripts/smoke-test-discovery.sh
```

It writes the discovered model to `out/smoke/discovery.json` for human inspection.

## Gate B: adversarial discovery

The fixture under `tests/fixtures/adversarial/discovery-torture` intentionally contains awkward and misleading inputs. Negative assertions are first-class tests. SAS-looking text inside quoted strings, unresolved dynamic targets, malformed/partial metadata, and sensitive connection material must not create fabricated certainty or leak secrets.

## Gate C: untouched public SAS corpus

Public SAS source artifacts are run through discovery without rewriting them to satisfy the parser. Assertions are limited to defensible invariants so the expected result is not retrofitted to the implementation.

## Interpretation

A failure is evidence to investigate. Determine whether it is an implementation defect, an explicitly unsupported construct, or an invalid assertion. Do not weaken an assertion simply to make the suite green.

See `docs/TESTING.md` for the complete evidence ladder and the real-runtime/parity layers that remain future work.
