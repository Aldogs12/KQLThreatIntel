## GhostCode: Threat Overview


GhostCode abuses the OAuth 2.0 device authorisation grant (RFC 8628) to steal Microsoft tokens. Because the victim authenticates on Microsoft's own legitimate sign-in page, there is no credential harvesting portal to detect and MFA provides no protection. The MFA claim is carried forward into the stolen token, so every subsequent attacker API call passes authentication checks without challenge.

Delivery is notable for being Business Email Compromise (BEC-style) rather than bulk phishing. Operators approach targets through web contact forms posing as procurement officers from impersonated US distributors, build rapport with the sales team, then deliver an Non-Disclosure-Agreement (NDA) lure via WeTransfer containing a password-protected HTML file. Over 30 lookalike domains registered in August 2026 suggest a broader campaign against service providers.

Overlaps exist with Storm-2372 (post-auth objectives) and EvilTokens (AES-GCM gated HTML), but the PBKDF2 password-derived key, three-layer obfuscation stack and `python-requests` user agent are not documented elsewhere.

> The activity described here was observed against a UK-based victim, with US companies used as impersonation lures. The technique is geography-agnostic: the proxy infrastructure simply rotates to match wherever the target sits, so Australian organisations should treat this as equally applicable rather than a distant problem.

### Behaviour

**Delivery.** A password-protected HTML lure stacks three evasion layers: junk padding to break similarity hashing, HTML comments injected between every visible character to defeat regex and OCR classifiers, and an AES-256-GCM encrypted redirect URL. The destination stays hidden from DNS, proxy and sandbox telemetry until the victim enters the password. A JavaScript challenge, Cloudflare Turnstile and a server-side user-agent blocklist filter out analysts and crawlers.

**Authentication.** The phishing server acts as the OAuth client using the Microsoft Authentication Broker App ID `29d9ed98-a469-4536-ade2-f981bc1d605e`, requests a device code, injects the `user_code` into the page, and polls Microsoft while the victim signs in and completes MFA. A decoy NDA is served afterwards to reduce suspicion.

**Post-compromise.** Token abuse began five seconds after authentication. Within 78 seconds the operators took a Primary Refresh Token, registered three Entra devices and enrolled one into Intune. Device names followed `firstname-lastname-companydomain-<8 hex>`. Rotating residential proxies in the victim's own country made the consent prompt look plausible and kept impossible-travel logic quiet.

**Key takeaway:** the persistence window closes before most manual triage begins, and the Intune device record survives token revocation.

---

### KQL ideas

Device code authentication followed by non-interactive activity from the same user:

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol == "deviceCode"
| where ResultType == 0
```

 The non-interactive logs are the key to these investigations and is where the actor lives. It is highly unusal for normal users to be using scriopted agents like python-request.


```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d)
| where UserAgent has_any ("python-requests", "curl", "go-http-client", "okhttp")
| summarize Calls = count(), Resources = make_set(ResourceDisplayName), IPs = make_set(IPAddress, 20)
    by UserPrincipalName, UserAgent, bin(TimeGenerated, 1h)
| order by Calls desc
```

Device registerations rapidly follow upon successful access. This makes eviciting the threat actors harder and provides a foothold in the environment.

```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName has "Add registered device" or OperationName has "Register device"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend DeviceName = tostring(TargetResources[0].displayName)
| summarize Registrations = count(), Devices = make_set(DeviceName)
    by Actor, bin(TimeGenerated, 5m)
| where Registrations >= 2
```

Entra devices matching the kit naming convention:

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| extend DeviceName = tostring(TargetResources[0].displayName)
| where isnotempty(DeviceName)
| where DeviceName matches regex @"^[a-z]+-[a-z]+-[a-z0-9]+-[a-z]{2,}-[a-f0-9]{8}(-p[0-9]{2})?$"
| project TimeGenerated, DeviceName, OperationName, Actor = tostring(InitiatedBy.user.userPrincipalName)
```

Primary Refresh Token issuance shortly after a device code event is also worth baselining, using `IncomingTokenType == "primaryRefreshToken"` in `AADNonInteractiveUserSignInLogs`, though volumes vary heavily by tenant so tune before alerting.

### Immediate mitigations

Block the `deviceCode` authentication flow in Conditional Access for all users except documented exceptions. This single control neutralises the kit. Beyond that, alert on multiple device registrations originating from a single session, require compliant devices where feasible, and treat Intune enrolment records as a separate eradication step from token revocation, as the device record persists after the token is revoked. Finally, if your organisation uses Microsoft Sentinel, confirm that the `NonInteractiveUserSignInLogs` category is enabled in your Entra ID diagnostic settings. Without it, the entire post-authentication phase of this attack is invisible.

> [!NOTE]
> Research is always credited to the vendor whose intelligence I have drawn on, unless the analysis is my own. These commits provide quick, practical next steps for IT professionals and security analysts, with a focus on the Microsoft security stack. Detection logic is provided as-is and should be tuned and validated against your own environment before production use.

Sources: https://www.esentire.com/blog/ghostcode-dissecting-a-novel-device-code-phishing-kit 