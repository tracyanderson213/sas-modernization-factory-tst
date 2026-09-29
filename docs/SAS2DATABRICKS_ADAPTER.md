# sas2databricks Adapter Behavior

The upstream `s2db convert` command emits generated code followed by a one-line
conversion summary such as:

```text
model=opus-4.8 target=pyspark steps=1 review=1 llm_escalations=1
```

That line is CLI metadata, not valid Python or Spark SQL.

The SMF adapter strips the summary line before writing the generated artifact
and stores the parsed values in conversion-provider metadata.

A non-zero `review` count changes the SMF conversion status to
`review_required`.

The Validation Engine independently inspects generated artifacts for review
markers such as `[REVIEW]`, `MANUAL REVIEW`, low-confidence annotations, and
`pending host fulfillment`.

This is intentional defense in depth. Converter-reported uncertainty must not
be lost merely because the generated artifact is syntactically valid.
