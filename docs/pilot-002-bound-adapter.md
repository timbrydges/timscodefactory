# Pilot 002 bound adapter

`run_bound_once` composes the pinned request codecs, fixed one-shot transport,
signed allowance verification and permanent attempt ledger. It is disabled by
default and has no live handler. Deployment must own all context, qualifications,
readiness, trusted keys, credential loading and activation configuration; these
must never come from untrusted invocation fields.

The adapter requires a fresh provider rate qualification that names the exact
role, model, task, source commit, contract, packet and complete request digest.
It requires externally qualified complete input and combined output bounds,
standard text-only rates with no cache charges, a source-evidence digest and a
window no longer than 24 hours. Rates are nonnegative integer micro-USD per
million tokens. Output bound must match the request's 4096 tokens; input bound
must be positive and at most 32768. Paid qualifications require a positive total.
The Google-only exception in `pilot-002-google-free-tier.md` requires an unlinked
free-tier billing observation and a signed window of at most five minutes.

Both the maximum reservation quote and observed usage cost use integer arithmetic
rounded up to a micro-dollar. The maximum must not exceed USD 0.25. The complete
rate qualification is hashed into pricing evidence and therefore into the signed
owner allowance. A changed rate invalidates the signature even if rounding leaves
the maximum unchanged. Qualification input and returned pricing are copied.

The wrapper constructs the concrete adapter and supplies its own derived pricing
to the existing workflow. That workflow verifies the owner signature before
claiming the permanent role and loading credentials. The adapter checks pricing
freshness again before transmission, retains its local attempt latch on failure,
and remembers the digest of the successful transport response. Parsing rejects
bytes not returned by that attempt, reconstructs the task bindings, checks observed
usage against qualified bounds and computes the rounded usage cost. Timely calls
can be accounted for after expiry without reopening an attempt.

The workflow's `actual_micro_usd` field is the conservative usage-derived amount
at qualified rates, not an independently reconciled provider invoice. The returned
completion remains unsigned and has no gate or release authority. In-process
response binding is not durable signed evidence and cannot prove billing outside
the reviewed process. No standalone parser result can satisfy that binding.

The adapter validates qualification structure and scope; it does not establish
that the rates, token ceilings, model access or provider billing rules are true.
Those still need fresh independent evidence, especially Google's combined thought
and visible-output ceiling. No production qualification or signed allowance is
created here. Live runtime packaging, credential permissions, evidence signing,
readiness and explicit activation remain required.

Tests use real local signing, codecs, adapter and workflow with synthetic provider
responses, fake HTTPS connections and an in-memory conditional claim fixture.
They verify all three roles, request/rate/response substitution, expiry, cost
rounding, uncertain transport outcomes and cross-instance duplicate blocking.
They neither call providers nor mutate AWS state.
