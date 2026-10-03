# Pilot 002 published candidate binding

This read-only verifier compares already-fetched Git objects with the exact,
bounded Builder response and the pinned task contract. It requires one child
commit directly on the approved baseline, changes confined to the two allowed
files, ordinary non-executable blob modes, and byte-for-byte response equality.
It reads objects without checking out or executing candidate code. Replacement
objects and inherited Git routing are disabled. The supplied repository and Git
executable must be deployment-controlled. Subprocess output is checked after
capture; this is not a general hostile-repository resource sandbox.

`scripts/verify_pilot002_candidate.py` takes the local repository directory,
candidate commit, Builder response file and a new output file. Existing `gh`
authentication reads the commit and exact task branch from github.com. Both must
match the locally verified tree, commit and baseline parent. The script does not
fetch, create a commit, publish a branch, sign evidence, run tests or invoke a model.

The library's GitHub reader is deployment-owned, never an invocation-provided
observation. The CLI records observation time and hashes returned GitHub data.
This unsigned snapshot carries no gate or release authority. A branch can move
after observation; future runtime integration must refetch and impose freshness
and signed binding requirements. Passing this check alone does not establish
provider readiness or authorize an attempt. No live candidate exists yet, so
current validation uses isolated local Git fixtures and injected GitHub responses.
