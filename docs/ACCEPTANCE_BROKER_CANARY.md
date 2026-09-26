# Disabled acceptance broker deployment probe

This deployment proves only that a pinned broker Lambda can respond to an exact
model-free probe. The function rejects provider-call events; its execution role
can write only to its own CloudWatch log group. No provider secret, DynamoDB,
Builder invocation, scheduler, or release permission is attached.

Run from a clean checkout of the reviewed main commit in AWS CloudShell, in
`ca-central-1`, using the approved account `666730517561`:

```sh
python3 scripts/build_manifest.py --check
python3 scripts/build_acceptance_broker_package.py /tmp/factory-acceptance-broker-canary.zip
python3 scripts/prepare_acceptance_broker_canary.py prepare /tmp/factory-acceptance-broker-canary.zip /tmp/factory-acceptance-broker-plan.json
```

Read `/tmp/factory-acceptance-broker-plan.json` and confirm its four `Add`
resources, code hash, source commit, and `model_calls_authorized: 0`. The
`prepare` command uploads a versioned ZIP and creates a change set; it does not
execute the change set.

```sh
python3 scripts/prepare_acceptance_broker_canary.py execute /tmp/factory-acceptance-broker-plan.json
python3 scripts/prepare_acceptance_broker_canary.py verify /tmp/factory-acceptance-broker-plan.json
```

The verification command checks the deployed role policies, pinned Lambda
version, code hash, disabled flag, and exact probe result. It writes
`/tmp/acceptance-broker-canary-evidence.json` for later review. This proof does
not clear any live activation gate or authorize a model call.
