# QA role transport

The generic Lambda role protocol accepts the immutable version ARN
`arn:aws:lambda:ca-central-1:666730517561:function:tims-factory-qa:<version>`
for `qa_engineer_service`. Activation, reservation and invocation all reject a
lease whose role or authoritative identity differs from the configured function.
This prevents misrouted work from reaching even the budget guard.

QA uses the same signed scope, durable execution claim, signed result and
receipt verification as the other roles. An uncertain provider attempt remains
STARTED and cannot execute again. Retained complete responses may be read back
without making another provider call.

This library change grants no deployment or invocation rights. The historical
Lambda handler and controller remain restricted to their existing contracts.
A fresh controller still needs separate provider guards, exact signed scope,
immutable function/source pins, deployment-owned review validators, authenticated
fresh test proof, and a bounded budget before runtime activation. Historical
handoff receipts cannot authorize this protocol.
