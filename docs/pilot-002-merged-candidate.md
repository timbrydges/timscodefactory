# Read-only merged candidate verification

`scripts/verify_pilot002_merge.py REPOSITORY CANDIDATE MERGE PR BUILDER_RESPONSE OUTPUT`
verifies the original Builder bytes and published candidate branch, then reads
the exact GitHub PR, merge commit and current main reference. It requires the
same repository, candidate head and branch, closed merged PR, exact candidate
tree, and exactly two ordered parents: the approved baseline and candidate.
Main must still point to that merge. Drift stops verification; this helper is
not a general historical merge verifier or a squash/rebase verifier.

The output is an observation, not a signed receipt or owner authorization.
It never executes candidate code, changes repository state, accesses AWS,
calls models, refunds budgets, or advances Factory state. All authority flags
remain false. Independent CI supplies test evidence separately. The reads are
not an atomic snapshot; a future consumer must check freshness and revalidate
the exact reference before any action rather than trusting this saved output.

Pilot 002's candidate was merged into the acceptance repository as
`994719a384b7ac96abeb67e4b2addcab2deb4763` under owner pre-approval 2.
Its tree equals the candidate tested by acceptance CI. Factory PR #394 records
that handoff and was merged using the owner's administrative override under
pre-approval 3; independent review was not performed. Repository rules and
runtime permissions were not changed.
