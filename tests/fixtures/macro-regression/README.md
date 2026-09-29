# TASK-05 macro regression fixtures

These files are SMF-authored synthetic inputs for the AD-03 strategy `1.0` static macro analyzer.
They are not copied from the public corpus or a client estate. The manifest binds every source by
relative path, byte size, and SHA-256 digest; the test-only loader reacquires those bytes and rejects
drift, undeclared files, traversal, symlinks, duplicate identity, unknown types, and success-like
attestations.

The expected results are regression assertions only. They do not claim executable SAS macro
expansion, target generation, execution, validation, parity, certification, or human approval.
