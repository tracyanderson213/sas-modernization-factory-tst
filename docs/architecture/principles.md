# Architecture Principles

## P1: Deterministic First

If a transformation can be implemented as a deterministic, tested rule, it should not depend on an LLM.

## P2: Validate Everything

Generated code is not considered migrated code until it has satisfied the required validation policy.

## P3: AI Is a Bounded Reasoning Capability

AI-assisted transformation should receive structured context, produce structured results, and operate within explicit retry and escalation boundaries.

## P4: Confidence Must Be Evidence-Based

Confidence should be derived from parser coverage, rule coverage, unsupported constructs, execution results, parity results, and other observable evidence.

## P5: Humans Resolve Exceptions, Not Routine Work

Engineering attention should be directed toward ambiguous, high-risk, or unsupported workloads.

## P6: Human Fixes Should Improve the Factory

Reusable engineer resolutions should become versioned transformation rules or validation patterns with regression tests.

## P7: Provenance Is Mandatory

The factory must be able to explain how a source workload became a target workload.

## P8: Deployment Policy Is Configuration

Client or environment-specific rules should remain outside generic factory code wherever possible.

## P9: No Sensitive Data in Source Control

Production/client data, credentials, secrets, and protected artifacts must never be committed.
