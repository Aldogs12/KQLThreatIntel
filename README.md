# KQLThreatIntel

Weekly threat intelligence write-ups turned into practical detection steps for the Microsoft security stack.

Vendor reports are written to be read rather than actioned. A twenty-minute report usually reduces to a few detection opportunities and one configuration change. This repository does that reduction, focused on Microsoft Sentinel, Defender XDR and Entra ID.

## Entry format

- Short overview of the threat and why it matters
- Behaviour: delivery, execution, post-compromise
- Indicators, grouped by the log source they appear in
- KQL for Sentinel or Advanced Hunting
- Immediate mitigations, prioritised by impact

## Before you hunt

Several entries depend on log sources that are off by default. Check your Entra ID diagnostic settings for `NonInteractiveUserSignInLogs` in particular, as it is the most commonly missing source and hides the most attacker activity.

Run the broadest query in an entry first to see whether the behaviour exists in your tenant, then tune thresholds to your own baseline.

## Attribution

Research is credited to the vendor whose intelligence I have drawn on, with a link to the original, unless the analysis is my own. Summaries are written in my own words.

## Disclaimer

> [!IMPORTANT]
> General guidance only. This is not a substitute for tailored consulting or advice from someone who knows your environment.

Every tenant differs in configuration, licensing, Conditional Access design and existing coverage. A query that is precise in one will be noisy in another, and a mitigation that is trivial for one organisation will break a critical workflow elsewhere.

Detection logic is provided as-is. Validate it in a read-only context, tune it, and put any configuration change through normal change management. Views are my own.
