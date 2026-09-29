# Conversion Examples

The Conversion Engine is wired into the current `smf` CLI.

Use a synthetic SAS example with:

```bash
smf convert examples/simple/example.sas --target pyspark --out out
```

For Spark SQL:

```bash
smf convert examples/simple/example.sas --target sparksql --out out
```

Conversion always performs assessment first. A workload routed as `human_supervised` is not automatically converted.

After conversion, validate the generated artifact:

```bash
smf validate \
  examples/simple/example.sas \
  out/example/example.py \
  --target pyspark \
  --out out \
  --explain
```

For eligible Python/PySpark-shaped output, local execution validation can then be invoked with:

```bash
smf execute \
  examples/simple/example.sas \
  out/example/example.py \
  --target pyspark \
  --provider local \
  --out out
```

Local execution is an engineering test path. It does not prove Databricks runtime compatibility or migration acceptance.
