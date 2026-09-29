import re

PROC_PATTERN = re.compile(r"\bproc\s+([a-zA-Z_][\w]*)\b", re.IGNORECASE)
DATA_STEP_PATTERN = re.compile(r"\bdata\s+([\w.]+)\s*;", re.IGNORECASE)


def detect_constructs(source: str) -> list[str]:
    constructs: set[str] = set()

    procedures = {match.upper() for match in PROC_PATTERN.findall(source)}
    for procedure in procedures:
        constructs.add(f"PROC {procedure}")

    if DATA_STEP_PATTERN.search(source):
        constructs.add("DATA STEP")

    patterns = {
        "CREATE TABLE": r"\bcreate\s+table\b",
        "SELECT": r"\bselect\b",
        "JOIN": r"\b(?:inner|left|right|full|cross)?\s*join\b",
        "GROUP BY": r"\bgroup\s+by\b",
        "ORDER BY": r"\border\s+by\b",
        "WHERE": r"\bwhere\b",
        "UNION": r"\bunion\b",
        "CASE": r"\bcase\b",
        "SUM": r"\bsum\s*\(",
        "COUNT": r"\bcount\s*\(",
        "AVG": r"\b(?:avg|mean)\s*\(",
        "MIN": r"\bmin\s*\(",
        "MAX": r"\bmax\s*\(",
        "MERGE": r"\bmerge\b",
        "SET": r"\bset\s+[\w.]",
        "BY": r"\bby\s+[\w]",
        "RETAIN": r"\bretain\b",
        "ARRAY": r"\barray\b",
        "FORMAT": r"\bformat\b",
        "INFORMAT": r"\binformat\b",
        "LIBNAME": r"\blibname\b",
        "FILENAME": r"\bfilename\b",
        "CALL SYMPUT": r"\bcall\s+symputx?\b",
        "PROC SQL PASS-THROUGH": r"\bconnect\s+to\b",
    }

    for label, pattern in patterns.items():
        if re.search(pattern, source, flags=re.IGNORECASE):
            constructs.add(label)

    if re.search(r"%macro\b", source, flags=re.IGNORECASE):
        constructs.add("MACRO DEFINITION")

    if re.search(r"%include\b", source, flags=re.IGNORECASE):
        constructs.add("%INCLUDE")

    return sorted(constructs)
