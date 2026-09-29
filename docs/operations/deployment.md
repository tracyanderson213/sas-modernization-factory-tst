# Deployment

## Environments

Recommended minimum:

- local
- development
- validation/test
- production

## Configuration

Deployment-specific values belong under `deployments/<name>/` and environment-specific secret values belong in approved secret stores, not Git.

## Promotion

Infrastructure, factory code, transformation rules, agent definitions, and deployment configuration should all be versioned.

Production promotion should require:

- passing automated tests
- security/dependency scanning
- policy checks
- human approval
