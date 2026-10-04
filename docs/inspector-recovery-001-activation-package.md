# Inspector recovery activation packaging

The separately approved disabled recovery function was deployed from source
067177bddbcb091f0c7e2ecf78f3e87816b82d3d. The saved deployment evidence records
its exact versioned package, disabled flag, concurrency zero, logs-only role,
unchanged original attempts and unused recovery record.

The new offline activation packager composes the existing inert builder. It
validates the recovery activation schema, matching build source, pinned candidate,
Builder context and request, approved recovery scope, owner enrollment, current
cost qualification and readiness. Duplicate JSON keys, expired material, changed
bindings, revoked signers and over-cap rates are rejected. The output contains
the validated public activation and a regenerated file-hash manifest.

Packaging is not authorization. It includes no signed allowance, enables no
function and contacts no provider or AWS service. The existing disabled-deployment
renderer rejects this activation-bearing artifact. The CLI always checks the
current clock; historical time injection is for offline tests only. A successful
build validates document bindings, not the truth of external price/access
observations. Those observations and exact artifact still require review before
deployment, and the runtime rechecks expiry and the owner signature before any
recovery claim.

This source change does not deploy the activation package. Recovery-specific
owner signing integration, exact live permission/deployment validation and a
single-attempt runner with verified shutdown remain required. The original
Inspector attempt remains permanently consumed. No live recovery call has run.
