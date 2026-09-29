# Adversarial discovery fixture

This fixture is intentionally ugly. It is not designed around the parser's happy path.
It contains multiline LIBNAME statements, mixed case, dynamic macro references, comments and
quoted strings containing SAS-looking text, shell variables, commented shell invocations,
external scheduler dependencies, malformed scheduler metadata, and paths containing spaces.

The goal is not that every construct resolves. The goal is that SMF finds high-confidence facts,
does not invent false lineage, redacts secrets, preserves unknowns, and does not crash.
