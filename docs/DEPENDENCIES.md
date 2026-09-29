# Dependency Strategy

## Objective

The factory should remain modular. Engineers should not need every Azure, Databricks, AI, and conversion dependency merely to work on the core.

## Core

Installed with:

```bash
pip install -e .
```

Current core libraries:

- `jsonschema`: JSON Schema contract validation
- `pydantic`: typed internal models and structured validation
- `PyYAML`: factory, routing, policy, and rule configuration
- `rich`: CLI diagnostics and human-readable local output
- `typing-extensions`: compatibility for typing features

## Development

Installed with:

```bash
pip install -e ".[dev]"
```

Includes:

- pytest
- pytest-cov
- Ruff
- mypy
- pre-commit
- Python build tooling
- pip-audit
- typing stubs

## Conversion

```bash
pip install -e ".[conversion]"
```

Provides the external `sas2databricks` accelerator. The package is kept optional so the factory can later support additional conversion providers or its own engine.

## Azure

```bash
pip install -e ".[azure]"
```

Provides SDKs required for the planned Azure control plane.

## Databricks

```bash
pip install -e ".[databricks]"
```

Provides the Databricks SDK used by the execution-plane adapter.

## AI

```bash
pip install -e ".[ai]"
```

Provides the OpenAI Python SDK. Enterprise production configuration should target the approved Azure-hosted model endpoint.

## API

```bash
pip install -e ".[api]"
```

Provides FastAPI and Uvicorn for the future factory service/API.

## Dependency Policy

- Keep provider SDKs optional.
- Pin compatible major/minor ranges in `pyproject.toml`.
- Do not add dependencies merely for trivial utilities.
- Run `pip-audit` before pull requests and releases.
- Review upstream licenses before production distribution.
- Upgrade dependencies through reviewed pull requests.


## AI Providers

Install AI provider dependencies with:

\`\`\`bash
pip install -e ".[ai]"
\`\`\`

The factory currently supports development against:

- OpenAI / Azure OpenAI
- Anthropic Claude

AI providers are optional integrations and must remain behind the factory internal AI provider abstraction. Core factory components must not depend directly on a specific model provider.

Production deployments must use only enterprise-approved model endpoints and deployment policies.

Model selection is a deployment and routing decision, not a conversion-engine dependency.
