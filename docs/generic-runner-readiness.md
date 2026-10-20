# Generic runner readiness

This is a capability audit, not authorization to activate the runner. Repository
CI and fake-provider tests do not establish live unattended operation.

| Requirement | Implemented | Still required |
| --- | --- | --- |
| One generic runner on a schedule | Trusted task profiles, durable admission, bounded polling, fixed executable dispatch, pause and uncertain-attempt stops | Approved host/timer activation and an observed run with chat closed |
| One provider for the build loop | Builder and reviewer share the OpenAI adapter, pinned model, pricing and request limits | Accepted delivery through the complete live loop |
| Automatic credential renewal | Absolute expiry validation, exact scope checks, durable exchange limits, generic-host binding and bounded JWT exchange transport | Trusted host identity source, provider mapping, CLI selection and bounded live qualification |
| Real-repository proof | Bonus Library source was used for bounded attempts; timestamp correction passed a separately approved local test | Qualify the later hardening candidate, full app checks, owner-isolation evidence and browser acceptance; publication needs its own approval |

## Evidence boundaries

- `development_profile.py`, `development_schedule.py`,
  `development_schedule_host.py` and `scripts/development_schedule.py` provide the
  scheduling path. The CLI defaults disabled and installs no OS timer.
- `development_composition.py` binds one provider to both stages. Its renewable
  option requires an exact credential-source pin. The current executable still
  selects the environment-key path; there is no silent migration.
- `credential_issuance.py`, `renewable_credentials.py`,
  `workload_identity_response.py` and `workload_identity_transport.py` implement
  the renewal path. Their tests use fake tokens, clocks and network dependencies.
- Private acceptance evidence records a consumed seven-test local timestamp
  correction. The later query-parameter/empty-page candidate is prepared but has
  no fresh execution approval. Human correction is not autonomous repair proof.

## Next approval boundaries

1. Qualify the changed Bonus candidate in one pinned, network-disabled local test.
   This must use a fresh attempt; prior single-use tests cannot be replayed.
2. Choose the unattended host and durable state location, then approve exact
   identity-source access and provider mapping. Do not infer those permissions
   from repository merges or CI approval. Identity setup grants no model spend.
3. Approve a bounded identity-exchange qualification, including timing limits and
   cleanup, before connecting it to workflow execution.
4. After preflight passes, approve a fresh bounded runner attempt and its budget.
   Schedule activation, publication and deployment remain distinct scopes.

Until those steps are authorized, preserve all holds and disabled production
baselines. Continue local analysis, tests and repository review only. Do not claim
completion of the four requirements from merged code alone.
