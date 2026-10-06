# Exact state persistence

State transitions now condition the atomic state-and-audit transaction on the
existing version, state label, canonical payload and update timestamp. A missing
row no longer qualifies for an ordinary transition. Bootstrap remains a separate
conditional creation operation. Same-version changes to leases, evidence or
other payload fields cannot be silently overwritten by an older observation.

Legacy records with noncanonical payload serialization fail closed and require
explicit reconciliation; this change does not rewrite or migrate existing rows.

`scripts/state_cas_canary.py --execute NEW_JOURNAL.json NEW_RESULT.json` is a
single-use owner-operated AWS check. It uses only synthetic tasks
`state-cas-canary-001` and `state-cas-missing-001` in the existing state table.
It creates the first in PAUSED v0, proves missing/state/payload mismatches leave
no state or audit write, then records an exact PAUSED v0 to PAUSED v1 owner
transition. The second task must remain absent. Retain the fixture and audit.
Existing records or uncertain outcomes stop the canary without retry.

There are no provider calls, permission changes, deletions, pilot task updates,
worker invocations, schedule changes or budget mutations. The command requires
the existing authenticated owner session and is never wired into a worker.
