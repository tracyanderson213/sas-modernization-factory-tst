# Repository stabilization record — 2026-09-21

## Preservation boundary

Before cleanup, the read-only manifest inventoried 54 linked worktrees, 52 local branches, 38
remote branches, 62 pull requests, 38 standalone SMF checkouts, dirty and ignored files, unique
commits, canonical record state, reachability and recommended disposition.

- Local evidence: `.project-audit/repository-stabilization/preservation-before-cleanup-v2.json`
- SHA-256: `db659d370c329245b33a96bdbddaf5a0c1000b6d67250d95dec54668c9eb5980`
- Baseline at inventory: `origin/main` `0690b29a24380a09188f44e0f6b0b258b8d8f128`
- Default disposition: preserve on dirty, ignored/untracked, evidence-bearing, unique, open,
  incomplete, detached-ambiguous or unavailable-history state.

An initial candidate removal was rejected because ignored `out/` evidence existed. No state changed.
The manifest was strengthened to include ignored files; 48 of 54 linked worktrees and all 38
standalone checkouts were consequently preserved. The primary checkout and its `.gitignore`,
`.azure/`, and `scripts/login-local.sh` were untouched.

## Completed removals

Exactly one linked worktree had no tracked, untracked, ignored or evidence content, had no open PR,
was canonically complete, and had a head fully reachable from `origin/main`:

| Removed object | Recoverable commit | Proof |
| --- | --- | --- |
| worktree `.smf-agent-worktrees/dbenv01-closeout` | `2e77dc966cea47492885fd281d6f0f83e3a814ee` | commit is reachable from `origin/main`; DBENV-01 Issue is closed and Project is `Done / Foundation Complete` |
| local branch `ops/dbenv-01-closeout-20260920` | `2e77dc966cea47492885fd281d6f0f83e3a814ee` | removed non-forced with `git branch -d` after worktree removal |

The following terminal-PR remote branches were deleted only after the manifest proved their exact
head commits reachable from `origin/main`:

| Remote branch | Recoverable commit | PR |
| --- | --- | --- |
| `agent/aigw-01` | `a9b7204b7a09b1895b578fc4c5790a01deaf0c96` | #241 |
| `agent/aip-05-v1` | `4b013d1abc46cc9158e2ead34acdcb163cff9ea9` | #274 |
| `agent/airep-01` | `eb80dc62f546453d80dde02390b930760b59e029` | #257 |
| `agent/base-02-v2` | `2efa792e345fe936aecb7fc7f9c0ae241c603abb` | #248 |
| `agent/base-04-v2` | `03616d06df1e249579964c78b63e2c838a00336b` | #247 |
| `agent/base-08-v1` | `07f1d44a7d1d0ccc85994d72c19ad44891a7a0ef` | #242 |
| `agent/base-10-v1` | `b7172a447119d382af93682ed8cd87c7a40a6fab` | #258 |
| `agent/cv-04-v1` | `fe96e3f36fa5940b90de760c1253581b3db932e4` | #251 |
| `agent/dbpkg-01-v1` | `da07d609010f2dc903388ac4ab97894c1ee1321a` | #260 |
| `agent/dbpkg-04-v1` | `969b6d394d7bb7b1dca0e4b8922a396c42d8b3a9` | #250 |
| `agent/dbx-01-v1` | `6fc7fac9316c991a8949c75d1f924fa73d1e244d` | #262 |
| `agent/dbx-04-v1` | `e27c613641e358042f5bc8917f1ff16c289a1348` | #266 |
| `agent/fail-01-v1` | `ae4371b78504abbbcc77e5c907c9d524548b59f5` | #259 |
| `agent/orch-01-v1` | `bfd57c92887687a6e394fd0d5a31a576d4b06e63` | #261 |
| `agent/orch-03-v1` | `cf3ffb0fe9a0ef4eee433b3a39a6e642a704edf2` | #264 |
| `agent/scale-01` | `af8c4a6507dc0ca1b263b5ba1bcb654bd725ebbd` | #246 |
| `agent/schema-int-01-v1` | `b9919c7798ca5ea08a1f6aebcd2b59e81b230f91` | #265 |
| `agent/spike-02-v1` | `3e52eb34313e12b199ccad910b5f84ea0e2cce76` | #271 |
| `agent/task-11-v1` | `c127b95bbd834efdea5f2ff60c4cbc4a32d19a1a` | #269 |
| `agent/task-12-v1` | `0033a3f828629fbd516fbbea1c194a9a6f47bb91` | #273 |
| `agent/task24-v1` | `2f584717701d0d66611d229c9d7323d5b6e6393e` | #275 |
| `agent/task25-v1` | `8429706c35e8bcc63f8511e0899850fdcc633af0` | #276 |
| `agent/vs-01` | `328fa0b5ff63aacbac2d0864d7478efb840314a8` | #244 |
| `fix/acceptance-exact-source-adoption` | `f45aab153929bec893ca83ab11133568b35b1de0` | #231 |
| `integration/dbenv-01` | `a9d015678b10eca3a788054e2438853d0c39e69f` | #230 |
| `integration/dbx-03-v2` | `c08dffc31f0966d95026fcc276e91c040c820b12` | #233 |
| `integration/lic-base-07-v2` | `4bf241e496494e7caf57c976e971e2d7f4a5d2a4` | #232 |
| `integration/recovery-first-wave-six` | `b774de420e59fbf36dc65d6c16fe15bcd5618767` | #226 |
| `integration/recovery-wave-pkg-corpus-base06-v1` | `e1d35ba4c31b7ccf1c3a922d96baaa69f2a400ee` | #237 |
| `planning/sep27-deadline-dashboard` | `fc523cbcd5c0d71ab8a03aa1570fe183dafe6f17` | #240 |

Stale worktree registrations and remote-tracking refs were pruned after a dry run. No force delete,
hard reset, clean, stash, recursive removal, or history rewrite was used.

The post-cleanup read-only verification manifest is
`.project-audit/repository-stabilization/post-cleanup-verification.json` (SHA-256
`097a31614776d11aad299205c2565cd237bf4fc9a4b26a732b0e7638e7694eff`). It confirms:

- `origin/main` and the remote read-back both remain
  `0690b29a24380a09188f44e0f6b0b258b8d8f128`;
- 53 linked worktrees remain: 48 preserved for ignored/untracked content, three preserved dirty, and
  two preserved because their canonical association or completion is ambiguous;
- 51 local branches and eight remote branches remain, with zero additional conclusively safe
  removal candidates;
- no pull request is open;
- the ownership map has no duplicate work identifiers or overlapping file boundaries; and
- the report explicitly identifies obsolete bases, unassociated historical lanes, and dirty
  protected files for human disposition rather than deleting them.

The 38 standalone SMF checkouts recorded by the pre-cleanup manifest remain preserved. The
post-cleanup verification deliberately rescanned only the linked-worktree control plane and the
temporary stabilization area; it does not reinterpret omission from that narrower scan as removal.

## Clean team baseline

`/private/tmp/smf-team-baseline-20260921` was freshly cloned and independently verified:

- `HEAD == origin/main == 0690b29a24380a09188f44e0f6b0b258b8d8f128`;
- tree `e2e7c9f840ab48b163574920bc01a95a90045927`, ahead/behind `0/0`;
- clean porcelain status before and after verification;
- `git fsck --no-dangling` and worktree/index diff checks passed;
- Python 3.12.13 from the existing shared `.venv`, with `smf` imported from the baseline `src/`;
- generated plan/config validation passed for all 208 records; 25 competition-plan tests passed.

This baseline is a verified starting point, not a permanent shared mutable checkout. Engineers should
create their own clean clone/worktree from fresh `origin/main` and use the ownership/integration-train
rules in [TEAM_ONBOARDING.md](TEAM_ONBOARDING.md).
