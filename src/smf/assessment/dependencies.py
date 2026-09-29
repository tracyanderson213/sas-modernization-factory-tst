import re

from smf.assessment.models import DependencySummary

TABLE_NAME = r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)?"


def _unique(values: list[str]) -> list[str]:
    return sorted(dict.fromkeys(values), key=str.lower)


def extract_dependencies(source: str) -> DependencySummary:
    outputs: list[str] = []
    inputs: list[str] = []

    outputs.extend(
        re.findall(
            rf"\bcreate\s+table\s+({TABLE_NAME})",
            source,
            flags=re.IGNORECASE,
        )
    )

    outputs.extend(
        re.findall(
            rf"\bdata\s+({TABLE_NAME})\s*;",
            source,
            flags=re.IGNORECASE,
        )
    )

    inputs.extend(
        re.findall(
            rf"\bfrom\s+({TABLE_NAME})",
            source,
            flags=re.IGNORECASE,
        )
    )

    inputs.extend(
        re.findall(
            rf"\bjoin\s+({TABLE_NAME})",
            source,
            flags=re.IGNORECASE,
        )
    )

    inputs.extend(
        re.findall(
            rf"\bset\s+({TABLE_NAME})",
            source,
            flags=re.IGNORECASE,
        )
    )

    inputs.extend(
        re.findall(
            rf"\bmerge\s+({TABLE_NAME})",
            source,
            flags=re.IGNORECASE,
        )
    )

    includes = re.findall(
        r"%include\s+(?:'([^']+)'|\"([^\"]+)\"|([^;\s]+))",
        source,
        flags=re.IGNORECASE,
    )
    include_values = [next(value for value in group if value) for group in includes if any(group)]

    macros_defined = re.findall(
        r"%macro\s+([A-Za-z_][\w]*)",
        source,
        flags=re.IGNORECASE,
    )

    all_macro_tokens = re.findall(
        r"%([A-Za-z_][\w]*)\s*(?:\(|;)",
        source,
        flags=re.IGNORECASE,
    )
    excluded_tokens = {
        "macro",
        "mend",
        "if",
        "then",
        "else",
        "do",
        "end",
        "let",
        "put",
        "include",
        "global",
        "local",
        "sysfunc",
        "eval",
        "sysevalf",
    }
    macros_invoked = [
        token
        for token in all_macro_tokens
        if token.lower() not in excluded_tokens
        and token.lower() not in {name.lower() for name in macros_defined}
    ]

    output_names = {name.lower() for name in outputs}
    inputs = [name for name in inputs if name.lower() not in output_names]

    return DependencySummary(
        inputs=_unique(inputs),
        outputs=_unique(outputs),
        includes=_unique(include_values),
        macros_defined=_unique(macros_defined),
        macros_invoked=_unique(macros_invoked),
    )
