# Threat Intel Case Files

Lifecycle reconstructions and ATT&CK mappings built from published threat intelligence reporting. Each case follows the same structure: objective, key judgments, actor profile, attack lifecycle, technique mapping, defensive actions, and lessons learned.

> **Note on scope:** these cases are analyst labs built from public vendor reporting, not original client engagements. There is no client or sensitive infrastructure data involved, and none has been redacted, because none exists in the source material. Every claim traces back to a cited public report, listed at the end of each case.

## Cases

| Case | Type | Summary |
|---|---|---|
| [Case 01](./case-01-APT38/README.md) | Threat actor lifecycle reconstruction | APT38's SWIFT fraud lifecycle, from third-party vendor reconnaissance through DYEPACK transaction manipulation to disk-wipe evidence destruction |
| [Case 02](./case-02-APT41/README.md) | Threat actor lifecycle reconstruction | APT41's dual-use toolkit, tracing how the same operators run state-tasked espionage and personal financially motivated crime through one shared malware set |

## Methodology note

Each case follows a structured analytic approach: define the intelligence question, collect from the available public source reporting, cross-reference claims across independent documents where more than one exists, map observed behavior to MITRE ATT&CK Enterprise techniques with an explicit tactic justification, and keep findings clearly separated from analytic judgment. Confidence levels, where stated, follow standard estimative language (low, moderate, high confidence) rather than presenting inference as established fact.
