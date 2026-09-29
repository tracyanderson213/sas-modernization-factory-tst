# Competition acceptance and planning coverage

208/208 records have a specification and body mapping. The approved DBENV records are materialized
locally; publication and launch remain limited to the exact authorization recorded in the plan.

## Scope counts

| Phase | Records |
| --- | ---: |
| competition-critical | 154 |
| competition-conditional | 18 |
| phase2 | 31 |
| later | 5 |
| Total | 208 |

## Recovery integrity

DP-01 remains unchanged. TASK-06 is deferred/P2 with Todo/Partial preservation constraints. The seven initially runnable roots are: `UPQ-01`, `CLICON-01`, `WLD-03`, `DBX-03`, `SASSEM-01`, `SASSEM-02`, `SASSEM-04`.

## Per-record inventory

| Key | Phase | Priority / horizon | Wave | Implementation dependencies | Review disposition |
| --- | --- | --- | ---: | --- | --- |
| [AD-01](AD-01.md) | competition-critical | P0 / P0 | 1 | SEC-05 | implement-or-close-evidence-gap |
| [AD-02](AD-02.md) | competition-critical | P0 / P0 | 1 | SEC-05 | revalidate-existing-foundation |
| [AD-03](AD-03.md) | competition-critical | P0 / P0 | 1 | AD-02 | revalidate-existing-foundation |
| [AD-04](AD-04.md) | competition-critical | P0 / P0 | 1 | CORPUS-01, CORPUS-03, CORPUS-05 | revalidate-existing-foundation |
| [AD-05](AD-05.md) | competition-critical | P0 / P0 | 1 | WLD-01, AD-02 | implement-or-close-evidence-gap |
| [AD-06](AD-06.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [AD-07](AD-07.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [AD-08](AD-08.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [AD-09](AD-09.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [AIGW-01](AIGW-01.md) | competition-critical | P0 / P0 | 1 | PKG-DES-01, CLICON-01, HENV-02, SEC-01, SEC-02, SEC-03 | implement-or-close-evidence-gap |
| [AIP-01](AIP-01.md) | competition-critical | P0 / P0 | 2 | CV-02 | implement-or-close-evidence-gap |
| [AIP-02](AIP-02.md) | competition-critical | P0 / P0 | 2 | AIP-01, AIP-05, SEC-04, ART-02 | implement-or-close-evidence-gap |
| [AIP-03](AIP-03.md) | later | P2 / P3 | 7 | — | implement-or-close-evidence-gap |
| [AIP-04](AIP-04.md) | competition-conditional | P1 / P1 | 5 | AIP-01, AIP-05 | implement-or-close-evidence-gap |
| [AIP-05](AIP-05.md) | competition-critical | P0 / P0 | 2 | AIP-01 | implement-or-close-evidence-gap |
| [AIREP-01](AIREP-01.md) | competition-critical | P0 / P0 | 2 | AIGW-01, CV-04, BASE-02 | implement-or-close-evidence-gap |
| [API-01](API-01.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [API-02](API-02.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [ART-01](ART-01.md) | competition-conditional | P1 / P1 | 5 | — | implement-or-close-evidence-gap |
| [ART-02](ART-02.md) | competition-critical | P0 / P0 | 0 | HENV-01 | implement-or-close-evidence-gap |
| [ASYNC-01](ASYNC-01.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [BASE-01](BASE-01.md) | competition-critical | P0 / P0 | 1 | CORPUS-05 | implement-or-close-evidence-gap |
| [BASE-02](BASE-02.md) | competition-critical | P0 / P0 | 1 | BASE-04, SASSEM-01, SASSEM-02, SASSEM-04 | implement-or-close-evidence-gap |
| [BASE-03](BASE-03.md) | competition-critical | P0 / P0 | 1 | BASE-02, HENV-02 | implement-or-close-evidence-gap |
| [BASE-04](BASE-04.md) | competition-critical | P0 / P0 | 1 | BASE-08, SCALE-01 | implement-or-close-evidence-gap |
| [BASE-05](BASE-05.md) | competition-conditional | P1 / P1 | 5 | — | implement-or-close-evidence-gap |
| [BASE-06](BASE-06.md) | competition-critical | P0 / P0 | 1 | WLD-03, BASE-07, TASK-04, SEC-05 | implement-or-close-evidence-gap |
| [BASE-07](BASE-07.md) | competition-critical | P0 / P0 | 1 | WLD-03, WLD-04, WLD-05, TASK-04, SEC-05 | implement-or-close-evidence-gap |
| [BASE-08](BASE-08.md) | competition-critical | P0 / P0 | 1 | UPQ-01, LIC-01, PKG-DES-01, CORPUS-11, BASE-06, BASE-07 | implement-or-close-evidence-gap |
| [BASE-09](BASE-09.md) | competition-critical | P0 / P0 | 2 | BASE-07, BASE-11, WLD-05, TASK-04 | implement-or-close-evidence-gap |
| [BASE-10](BASE-10.md) | competition-critical | P0 / P0 | 2 | BASE-02, BASE-03, HENV-02 | implement-or-close-evidence-gap |
| [BASE-11](BASE-11.md) | competition-critical | P0 / P0 | 2 | BASE-02, BASE-04, BASE-06, BASE-08, SCALE-01 | implement-or-close-evidence-gap |
| [BENCH-01](BENCH-01.md) | competition-critical | P0 / P0 | 4 | ORCH-02, HMET-01, SCORE-01 | implement-or-close-evidence-gap |
| [CLICON-01](CLICON-01.md) | competition-critical | P0 / P0 | 0 | HENV-02, SEC-01, SEC-02 | implement-or-close-evidence-gap |
| [COMP-01](COMP-01.md) | competition-critical | P0 / P0 | 4 | HPILOT-04, READY-02, PROV-02 | implement-or-close-evidence-gap |
| [CORPUS-01](CORPUS-01.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [CORPUS-02](CORPUS-02.md) | competition-critical | P0 / P0 | 1 | CORPUS-01, CORPUS-03, CORPUS-04, CORPUS-05, CORPUS-06, CORPUS-07, CORPUS-08, CORPUS-09, CORPUS-10 | revalidate-existing-foundation |
| [CORPUS-03](CORPUS-03.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [CORPUS-04](CORPUS-04.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [CORPUS-05](CORPUS-05.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [CORPUS-06](CORPUS-06.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [CORPUS-07](CORPUS-07.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [CORPUS-08](CORPUS-08.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [CORPUS-09](CORPUS-09.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [CORPUS-10](CORPUS-10.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [CORPUS-11](CORPUS-11.md) | competition-critical | P0 / P0 | 1 | UPQ-01, LIC-01 | implement-or-close-evidence-gap |
| [CV-01](CV-01.md) | competition-critical | P0 / P0 | 2 | CV-02, AD-03 | implement-or-close-evidence-gap |
| [CV-02](CV-02.md) | competition-critical | P0 / P0 | 2 | — | revalidate-existing-foundation |
| [CV-03](CV-03.md) | competition-critical | P0 / P0 | 2 | AD-04, CV-02 | implement-or-close-evidence-gap |
| [CV-04](CV-04.md) | competition-critical | P0 / P0 | 2 | UPQ-01, LIC-01, PKG-DES-01, BASE-02, CV-02 | implement-or-close-evidence-gap |
| [DBENV-01](DBENV-01.md) | competition-critical | P0 / P0 | 0 | HENV-01, HENV-02, SEC-01, SEC-02, CLICON-01 | implement-or-close-evidence-gap |
| [DBENV-02](DBENV-02.md) | competition-critical | P0 / P0 | 2 | DBENV-01, DBX-02, DBX-03, AIGW-01 | implement-or-close-evidence-gap |
| [DBENV-03](DBENV-03.md) | competition-conditional | P1 / P1 | 5 | DBENV-01, DBX-03, LIC-01, PKG-DES-01 | implement-or-close-evidence-gap |
| [DBPKG-01](DBPKG-01.md) | competition-critical | P0 / P0 | 2 | DBPKG-04, BASE-10, DBX-02, DBX-03 | implement-or-close-evidence-gap |
| [DBPKG-02](DBPKG-02.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [DBPKG-03](DBPKG-03.md) | competition-conditional | P1 / P1 | 5 | DBX-02, DBPKG-01 | implement-or-close-evidence-gap |
| [DBPKG-04](DBPKG-04.md) | competition-critical | P0 / P0 | 2 | BASE-02, BASE-08, SCALE-01, ORCH-04 | implement-or-close-evidence-gap |
| [DBX-01](DBX-01.md) | competition-critical | P0 / P0 | 2 | DBX-02, DBX-03, DBPKG-01, CV-04 | implement-or-close-evidence-gap |
| [DBX-02](DBX-02.md) | competition-critical | P0 / P0 | 2 | HENV-01 | implement-or-close-evidence-gap |
| [DBX-03](DBX-03.md) | competition-critical | P0 / P0 | 2 | HENV-01, HENV-02, SEC-01, SEC-02 | implement-or-close-evidence-gap |
| [DBX-04](DBX-04.md) | competition-critical | P0 / P0 | 2 | DBX-01, ORCH-04, PROV-01 | implement-or-close-evidence-gap |
| [DP-01](DP-01.md) | competition-critical | P0 / P0 | 3 | — | revalidate-existing-foundation |
| [DP-02](DP-02.md) | competition-critical | P0 / P0 | 3 | DBPKG-01, DBX-04, BASE-02 | implement-or-close-evidence-gap |
| [DP-03](DP-03.md) | competition-critical | P0 / P0 | 3 | DP-02, DBPKG-01, DBX-04 | implement-or-close-evidence-gap |
| [DP-04](DP-04.md) | competition-critical | P0 / P0 | 3 | DP-02, BASE-02, SASSEM-01, SASSEM-02, SASSEM-04 | implement-or-close-evidence-gap |
| [DP-05](DP-05.md) | competition-critical | P0 / P0 | 3 | DP-02, DBX-04 | implement-or-close-evidence-gap |
| [EPIC-AD](EPIC-AD.md) | competition-critical | P0 / P0 | 1 | — | implement-or-close-evidence-gap |
| [EPIC-AIP](EPIC-AIP.md) | competition-critical | P0 / P0 | 2 | — | implement-or-close-evidence-gap |
| [EPIC-API](EPIC-API.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [EPIC-ART](EPIC-ART.md) | competition-critical | P0 / P0 | 0 | — | implement-or-close-evidence-gap |
| [EPIC-ASYNC](EPIC-ASYNC.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [EPIC-BASE](EPIC-BASE.md) | competition-critical | P0 / P0 | 1 | — | implement-or-close-evidence-gap |
| [EPIC-CORPUS](EPIC-CORPUS.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [EPIC-CV](EPIC-CV.md) | competition-critical | P0 / P0 | 2 | — | implement-or-close-evidence-gap |
| [EPIC-DBPKG](EPIC-DBPKG.md) | competition-critical | P0 / P0 | 2 | — | implement-or-close-evidence-gap |
| [EPIC-DBX](EPIC-DBX.md) | competition-critical | P0 / P0 | 2 | — | implement-or-close-evidence-gap |
| [EPIC-DP](EPIC-DP.md) | competition-critical | P0 / P0 | 3 | — | implement-or-close-evidence-gap |
| [EPIC-HENV](EPIC-HENV.md) | competition-critical | P0 / P0 | 0 | — | implement-or-close-evidence-gap |
| [EPIC-HMET](EPIC-HMET.md) | competition-critical | P0 / P0 | 4 | — | implement-or-close-evidence-gap |
| [EPIC-HPILOT](EPIC-HPILOT.md) | competition-critical | P0 / P0 | 0 | — | implement-or-close-evidence-gap |
| [EPIC-HR](EPIC-HR.md) | competition-critical | P0 / P0 | 3 | — | implement-or-close-evidence-gap |
| [EPIC-MOD](EPIC-MOD.md) | phase2 | P2 / P2 | 6 | — | revalidate-existing-foundation |
| [EPIC-OPS](EPIC-OPS.md) | competition-critical | P0 / P0 | 4 | — | implement-or-close-evidence-gap |
| [EPIC-ORCH](EPIC-ORCH.md) | competition-critical | P0 / P0 | 2 | — | implement-or-close-evidence-gap |
| [EPIC-PROM](EPIC-PROM.md) | competition-critical | P0 / P0 | 3 | — | implement-or-close-evidence-gap |
| [EPIC-PROV](EPIC-PROV.md) | competition-critical | P0 / P0 | 2 | — | implement-or-close-evidence-gap |
| [EPIC-PV](EPIC-PV.md) | competition-conditional | P1 / P1 | 5 | — | implement-or-close-evidence-gap |
| [EPIC-REM](EPIC-REM.md) | competition-critical | P0 / P0 | 3 | — | implement-or-close-evidence-gap |
| [EPIC-SASSEM](EPIC-SASSEM.md) | competition-conditional | P1 / P1 | 5 | — | implement-or-close-evidence-gap |
| [EPIC-SEC](EPIC-SEC.md) | competition-critical | P0 / P0 | 0 | — | implement-or-close-evidence-gap |
| [EPIC-SV](EPIC-SV.md) | competition-critical | P0 / P0 | 3 | — | implement-or-close-evidence-gap |
| [EPIC-WLD](EPIC-WLD.md) | competition-critical | P0 / P0 | 1 | — | implement-or-close-evidence-gap |
| [FAIL-01](FAIL-01.md) | competition-critical | P0 / P0 | 2 | — | implement-or-close-evidence-gap |
| [HENV-01](HENV-01.md) | competition-critical | P0 / P0 | 0 | — | implement-or-close-evidence-gap |
| [HENV-02](HENV-02.md) | competition-critical | P0 / P0 | 0 | HENV-01 | implement-or-close-evidence-gap |
| [HENV-03](HENV-03.md) | competition-critical | P0 / P0 | 0 | SEC-01, HENV-01 | implement-or-close-evidence-gap |
| [HMET-01](HMET-01.md) | competition-critical | P0 / P0 | 4 | ORCH-04 | implement-or-close-evidence-gap |
| [HMET-02](HMET-02.md) | competition-critical | P0 / P0 | 4 | HMET-01 | implement-or-close-evidence-gap |
| [HMET-03](HMET-03.md) | competition-critical | P0 / P0 | 4 | HMET-01, ORCH-04 | implement-or-close-evidence-gap |
| [HMET-04](HMET-04.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [HPILOT-01](HPILOT-01.md) | competition-critical | P0 / P0 | 0 | — | implement-or-close-evidence-gap |
| [HPILOT-02](HPILOT-02.md) | later | P2 / P3 | 7 | — | implement-or-close-evidence-gap |
| [HPILOT-03](HPILOT-03.md) | competition-critical | P0 / P0 | 4 | HENV-01, ORCH-02 | implement-or-close-evidence-gap |
| [HPILOT-04](HPILOT-04.md) | competition-critical | P0 / P0 | 4 | ORCH-02, MIGOPS-01, PKG-QUAL-01 | implement-or-close-evidence-gap |
| [HR-01](HR-01.md) | competition-critical | P0 / P0 | 3 | REM-03 | implement-or-close-evidence-gap |
| [HR-02](HR-02.md) | competition-critical | P0 / P0 | 3 | HR-01, VAL-01 | implement-or-close-evidence-gap |
| [HR-03](HR-03.md) | competition-conditional | P1 / P1 | 5 | HR-02, PROV-01 | implement-or-close-evidence-gap |
| [LEARN-01](LEARN-01.md) | competition-conditional | P1 / P1 | 5 | PROV-01, FAIL-01, VAL-01, SEC-02 | implement-or-close-evidence-gap |
| [LIC-01](LIC-01.md) | competition-critical | P0 / P0 | 1 | UPQ-01, SEC-03 | implement-or-close-evidence-gap |
| [LOOP-01](LOOP-01.md) | competition-critical | P0 / P0 | 4 | ORCH-02, REM-01, HR-02 | implement-or-close-evidence-gap |
| [MIGCLI-01](MIGCLI-01.md) | competition-critical | P0 / P0 | 4 | CLICON-01, PROV-02, READY-02, PKG-QUAL-01, ORCH-01, ORCH-03, ORCH-04 | implement-or-close-evidence-gap |
| [MIGOPS-01](MIGOPS-01.md) | competition-critical | P0 / P0 | 4 | CLICON-01, MIGCLI-01, PROV-02 | implement-or-close-evidence-gap |
| [MOD-01](MOD-01.md) | phase2 | P2 / P2 | 6 | — | revalidate-existing-foundation |
| [MOD-02](MOD-02.md) | phase2 | P2 / P2 | 6 | — | revalidate-existing-foundation |
| [MOD-03](MOD-03.md) | phase2 | P2 / P2 | 6 | — | revalidate-existing-foundation |
| [MOD-04](MOD-04.md) | phase2 | P2 / P2 | 6 | — | revalidate-existing-foundation |
| [MOD-05](MOD-05.md) | phase2 | P2 / P2 | 6 | — | revalidate-existing-foundation |
| [MOD-06](MOD-06.md) | phase2 | P2 / P2 | 6 | — | revalidate-existing-foundation |
| [MOD-07](MOD-07.md) | phase2 | P2 / P2 | 6 | — | revalidate-existing-foundation |
| [MOD-08](MOD-08.md) | phase2 | P2 / P2 | 6 | — | revalidate-existing-foundation |
| [MOD-09](MOD-09.md) | phase2 | P2 / P2 | 6 | — | revalidate-existing-foundation |
| [MOD-10](MOD-10.md) | phase2 | P2 / P2 | 6 | — | revalidate-existing-foundation |
| [MODAP-01](MODAP-01.md) | competition-critical | P0 / P0 | 2 | BASE-09, WLD-11, WLD-12, MOD-02, MOD-08 | implement-or-close-evidence-gap |
| [MODCLI-01](MODCLI-01.md) | competition-critical | P0 / P0 | 4 | CLICON-01, MIGCLI-01, MODAP-01, PKG-QUAL-01 | implement-or-close-evidence-gap |
| [OPS-01](OPS-01.md) | competition-critical | P0 / P0 | 4 | ORCH-04, FAIL-01 | implement-or-close-evidence-gap |
| [OPS-02](OPS-02.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [OPS-03](OPS-03.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [OPS-04](OPS-04.md) | later | P2 / P3 | 7 | — | implement-or-close-evidence-gap |
| [ORCH-01](ORCH-01.md) | competition-critical | P0 / P0 | 2 | ORCH-04, FAIL-01 | implement-or-close-evidence-gap |
| [ORCH-02](ORCH-02.md) | competition-critical | P0 / P0 | 3 | MIGCLI-01, MIGOPS-01, READY-02, AIREP-01 | implement-or-close-evidence-gap |
| [ORCH-03](ORCH-03.md) | competition-critical | P0 / P0 | 2 | ORCH-01 | implement-or-close-evidence-gap |
| [ORCH-04](ORCH-04.md) | competition-critical | P0 / P0 | 2 | WLD-01 | implement-or-close-evidence-gap |
| [ORCH-05](ORCH-05.md) | competition-critical | P0 / P0 | 4 | ORCH-02, ORCH-03 | implement-or-close-evidence-gap |
| [ORCH-06](ORCH-06.md) | competition-conditional | P1 / P1 | 5 | ORCH-03 | implement-or-close-evidence-gap |
| [PKG-DES-01](PKG-DES-01.md) | competition-critical | P0 / P0 | 1 | UPQ-01, LIC-01, HENV-02 | implement-or-close-evidence-gap |
| [PKG-QUAL-01](PKG-QUAL-01.md) | competition-critical | P0 / P0 | 3 | AIGW-01, BASE-08, SCALE-01, CV-04, DBPKG-01, DBX-04, VAL-01, PROV-02 | implement-or-close-evidence-gap |
| [PROM-01](PROM-01.md) | competition-critical | P0 / P0 | 3 | PROV-01, VAL-01 | implement-or-close-evidence-gap |
| [PROM-02](PROM-02.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [PROM-03](PROM-03.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [PROV-01](PROV-01.md) | competition-critical | P0 / P0 | 2 | ORCH-04 | implement-or-close-evidence-gap |
| [PROV-02](PROV-02.md) | competition-critical | P0 / P0 | 3 | PROV-01, DBPKG-04, DBPKG-01, DBX-04, VAL-01, TASK-24, TASK-25 | implement-or-close-evidence-gap |
| [PV-01](PV-01.md) | competition-conditional | P1 / P1 | 5 | VAL-01, DBX-04 | implement-or-close-evidence-gap |
| [READY-01](READY-01.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [READY-02](READY-02.md) | competition-critical | P0 / P0 | 3 | DBX-04, VAL-01, PROV-02 | implement-or-close-evidence-gap |
| [REM-01](REM-01.md) | competition-critical | P0 / P0 | 4 | AIP-02, FAIL-01, VAL-01, REM-03 | implement-or-close-evidence-gap |
| [REM-02](REM-02.md) | competition-conditional | P1 / P1 | 5 | AIP-02, VAL-01 | implement-or-close-evidence-gap |
| [REM-03](REM-03.md) | competition-critical | P0 / P0 | 3 | FAIL-01, ORCH-04 | implement-or-close-evidence-gap |
| [SASSEM-01](SASSEM-01.md) | competition-critical | P0 / P0 | 1 | CORPUS-02 | implement-or-close-evidence-gap |
| [SASSEM-02](SASSEM-02.md) | competition-critical | P0 / P0 | 1 | CORPUS-02 | implement-or-close-evidence-gap |
| [SASSEM-03](SASSEM-03.md) | competition-conditional | P1 / P1 | 5 | CORPUS-02 | implement-or-close-evidence-gap |
| [SASSEM-04](SASSEM-04.md) | competition-critical | P0 / P0 | 1 | CORPUS-02, AD-03 | implement-or-close-evidence-gap |
| [SASSEM-05](SASSEM-05.md) | competition-conditional | P1 / P1 | 5 | CORPUS-02 | implement-or-close-evidence-gap |
| [SCALE-01](SCALE-01.md) | competition-critical | P0 / P0 | 2 | VS-01, DBX-03, PKG-DES-01 | implement-or-close-evidence-gap |
| [SCHEMA-INT-01](SCHEMA-INT-01.md) | competition-critical | P0 / P0 | 3 | DP-01, BASE-04, DBPKG-01 | implement-or-close-evidence-gap |
| [SCORE-01](SCORE-01.md) | competition-critical | P0 / P0 | 4 | HMET-01, VAL-01 | implement-or-close-evidence-gap |
| [SEC-01](SEC-01.md) | competition-critical | P0 / P0 | 0 | — | implement-or-close-evidence-gap |
| [SEC-02](SEC-02.md) | competition-critical | P0 / P0 | 0 | SEC-01 | implement-or-close-evidence-gap |
| [SEC-03](SEC-03.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [SEC-04](SEC-04.md) | competition-critical | P0 / P0 | 0 | SEC-02 | implement-or-close-evidence-gap |
| [SEC-05](SEC-05.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [SPIKE-01](SPIKE-01.md) | competition-conditional | P1 / P1 | 5 | — | implement-or-close-evidence-gap |
| [SPIKE-02](SPIKE-02.md) | competition-critical | P0 / P0 | 1 | AD-04, CV-02 | implement-or-close-evidence-gap |
| [SPIKE-03](SPIKE-03.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [SPIKE-04](SPIKE-04.md) | later | P2 / P3 | 7 | — | implement-or-close-evidence-gap |
| [SV-01](SV-01.md) | competition-critical | P0 / P0 | 3 | VAL-01 | implement-or-close-evidence-gap |
| [SV-02](SV-02.md) | competition-conditional | P1 / P1 | 5 | SV-01 | implement-or-close-evidence-gap |
| [TASK-01](TASK-01.md) | competition-critical | P0 / P0 | 1 | — | implement-or-close-evidence-gap |
| [TASK-02](TASK-02.md) | competition-critical | P0 / P0 | 1 | — | implement-or-close-evidence-gap |
| [TASK-03](TASK-03.md) | competition-critical | P0 / P0 | 1 | — | implement-or-close-evidence-gap |
| [TASK-04](TASK-04.md) | competition-critical | P0 / P0 | 1 | — | implement-or-close-evidence-gap |
| [TASK-05](TASK-05.md) | competition-critical | P0 / P0 | 1 | — | implement-or-close-evidence-gap |
| [TASK-06](TASK-06.md) | phase2 | P2 / P2 | 6 | — | implement-or-close-evidence-gap |
| [TASK-07](TASK-07.md) | competition-critical | P0 / P0 | 2 | — | implement-or-close-evidence-gap |
| [TASK-08](TASK-08.md) | competition-critical | P0 / P0 | 2 | — | implement-or-close-evidence-gap |
| [TASK-09](TASK-09.md) | competition-critical | P0 / P0 | 2 | — | implement-or-close-evidence-gap |
| [TASK-10](TASK-10.md) | competition-critical | P0 / P0 | 2 | — | implement-or-close-evidence-gap |
| [TASK-11](TASK-11.md) | competition-critical | P0 / P0 | 3 | — | implement-or-close-evidence-gap |
| [TASK-12](TASK-12.md) | competition-critical | P0 / P0 | 3 | — | implement-or-close-evidence-gap |
| [TASK-13](TASK-13.md) | competition-critical | P0 / P0 | 2 | — | implement-or-close-evidence-gap |
| [TASK-14](TASK-14.md) | competition-critical | P0 / P0 | 4 | — | implement-or-close-evidence-gap |
| [TASK-15](TASK-15.md) | competition-critical | P0 / P0 | 3 | — | implement-or-close-evidence-gap |
| [TASK-16](TASK-16.md) | competition-critical | P0 / P0 | 0 | — | implement-or-close-evidence-gap |
| [TASK-17](TASK-17.md) | later | P2 / P3 | 7 | — | implement-or-close-evidence-gap |
| [TASK-18](TASK-18.md) | competition-critical | P0 / P0 | 4 | — | implement-or-close-evidence-gap |
| [TASK-19](TASK-19.md) | competition-conditional | P1 / P1 | 5 | — | implement-or-close-evidence-gap |
| [TASK-20](TASK-20.md) | competition-conditional | P1 / P1 | 5 | — | implement-or-close-evidence-gap |
| [TASK-21](TASK-21.md) | competition-critical | P0 / P0 | 1 | — | implement-or-close-evidence-gap |
| [TASK-22](TASK-22.md) | competition-critical | P0 / P0 | 1 | — | implement-or-close-evidence-gap |
| [TASK-23](TASK-23.md) | competition-critical | P0 / P0 | 2 | — | implement-or-close-evidence-gap |
| [TASK-24](TASK-24.md) | competition-critical | P0 / P0 | 3 | — | implement-or-close-evidence-gap |
| [TASK-25](TASK-25.md) | competition-critical | P0 / P0 | 3 | — | implement-or-close-evidence-gap |
| [TASK-26](TASK-26.md) | competition-critical | P0 / P0 | 0 | — | implement-or-close-evidence-gap |
| [UPQ-01](UPQ-01.md) | competition-critical | P0 / P0 | 0 | SEC-03 | implement-or-close-evidence-gap |
| [VAL-01](VAL-01.md) | competition-critical | P0 / P0 | 3 | SCHEMA-INT-01, DP-02, DP-03, DP-04, DP-05, DBX-04 | implement-or-close-evidence-gap |
| [VS-01](VS-01.md) | competition-critical | P0 / P0 | 1 | BASE-08, PROV-01 | implement-or-close-evidence-gap |
| [WLD-01](WLD-01.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [WLD-02](WLD-02.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [WLD-03](WLD-03.md) | competition-critical | P0 / P0 | 1 | WLD-01, TASK-03, SEC-05 | implement-or-close-evidence-gap |
| [WLD-04](WLD-04.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [WLD-05](WLD-05.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [WLD-06](WLD-06.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [WLD-07](WLD-07.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [WLD-08](WLD-08.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [WLD-09](WLD-09.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [WLD-10](WLD-10.md) | competition-critical | P0 / P0 | 1 | — | revalidate-existing-foundation |
| [WLD-11](WLD-11.md) | phase2 | P2 / P2 | 6 | — | revalidate-existing-foundation |
| [WLD-12](WLD-12.md) | phase2 | P2 / P2 | 6 | — | revalidate-existing-foundation |
| [WLD-13](WLD-13.md) | phase2 | P2 / P2 | 6 | — | revalidate-existing-foundation |
