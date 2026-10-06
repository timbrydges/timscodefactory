# Paid-tier QA recovery accepted

The Factory Google project was verified as Tier 1 Prepay after linking its
existing billing account. No credits were purchased or reload settings changed.
The new isolated recovery002 made one Gemini request on source
`ccfd8860b2a665a295cd66db4ecdfb45ea36e97f`, returned signed ACCEPTED at
2026-10-06 05:57:28 UTC, and restored disabled code and zero concurrency at
05:57:36 UTC. Reported provider cost is USD0.004979; invoices are not verified.

The original QA and recovery001 claims remain consumed with USD0.25 holds each
and unknown actual charges. Recovery002 is COMPLETE with its USD0.25 hold
retained. All 20 observed components are disabled; Pilot002 remains PAUSED
version 0 with no active leases. Conservative batch allocation is USD1.25 of
the authorized USD2 ceiling. No old attempt was reset or retried.

`python scripts/verify_handoff003_qa_paid_recovery_evidence.py` independently
verifies the saved owner and QA signatures, exact candidate output, claim,
cost observation, and shutdown. This is historical evidence, not live gate
authority. The original dispatcher QA claim remains incomplete. Completing
a fresh controller chain still requires separate exact authority and claims.
