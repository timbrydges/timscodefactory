# Local scheduled development host

The development_schedule.py CLI defaults to disabled and installs no background service or OS timer. The operator must explicitly enable an action and confirm owner authorization. Initialization creates a paused schedule. Admission writes one immutable packet, but does not dispatch it. Resume and polling are separate actions.

Each packet contains exactly pins, approval, pricing, contract (the exact UTF-8 contract text) and execution_profile. The approval pins must match the packet pins. The profile digest, contract digest, clean Factory commit, repository snapshot, pricing, approval expiry and exclusive consumption receipt are checked by the existing fixed development entrypoint before model execution. No packet can choose an executable, module, host repository path or credential name.

The operator chooses the host directory and source repository directory. Packet files and materialized inputs are retained for reconciliation. They must contain no credentials. Provider credentials remain supplied separately through the existing process environment and are never written by the schedule host.

Polling is bounded by an explicit tick count and interval. Each tick claims at most one due job. Pause prevents new claims; it cannot cancel an already claimed external call. Jobs marked STARTED are never reclaimed after interruption. Exceptions and unknown dispatcher outcomes require reconciliation, stop polling and never trigger a retry. Outcome counts preserve earlier failures even if later ticks are idle.

A schedule record and the owner flag are not public authentication mechanisms. Keep this CLI and its local files under trusted operator control. A service deployment needs its own explicitly approved host/credential configuration and admission boundary. Repository tests use fake execution and do not authorize or demonstrate unattended production operation.

No model call, cloud change, credential rotation, timer installation or production activation is authorized by this implementation or its CI.
