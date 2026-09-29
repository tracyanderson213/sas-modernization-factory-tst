# Evidence-to-regression promotion records

This directory stores auditable links between corpus evidence that exposed an SMF defect and
the permanent SMF-owned regression that prevents recurrence.

A record moves through `observed -> reproduced -> fixed -> promoted`. Public evidence remains
untouched. Private-client evidence may only point to a shared regression after the behavior is
independently reproduced or sanitized, and the shared fixture must contain no client material.

Do not create a promotion record merely because a public workload is interesting. A record
represents an observed factory deficiency with a reproducible regression contract.
