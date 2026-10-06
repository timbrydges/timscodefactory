# Independent fixed-contract scope review

`FixedScopeReview` reviews only the bounded fingerprint exercise. Its canonical
contract names the two permitted paths, unchanged pinned candidate, source and
test-proof digests, the three distinct provider routes, one attempt per role,
zero retries, USD0.25/0.75/2.75 role/run/aggregate reservations and no release.
It rejects a different contract even if that contract has an owner signature.

Before approving scope, the policy checks the authoritative task stage/version,
exact prepared dispatch and candidate input, independent executor/reviewer
identities, absence of active work, a maximum fifteen-minute lease, and the
state machine's permission to delegate. It verifies the owner's real capability
signature and requires the fixed evidence requirement and stop condition.
Owner and review receipts are limited to ten minutes and cannot outlive the
lease. The pinned independent Docker proof must still show all 17 tests passing.

The deployment must authenticate the candidate repository and exact-source
Docker artifact before constructing the policy. Matching hashes and synthetic
fixtures do not establish provenance. This module reviews work scope; it does
not approve candidate correctness, convert custody evidence into a review,
advance a state, reserve money, call a model or authorize production release.

`ReviewScopeSigner` uses only the separately approved Product Spec role and key,
and defaults to disabled. It signs exactly the receipt produced by the policy,
rechecking live state, owner authorization, test proof and current enrollment
before and after KMS signing. The inherited signing attempt latch prevents a
local retry after an unknown remote outcome. Deployment clients must disable
SDK retries. No workflow or deployed endpoint is added by this change.

The historical handoff/canary receipts and all previous attempt claims remain
non-reusable. Tests use synthetic task/proof fixtures only, with real Ed25519
signatures; no test result is enrolled as live scope authority.
