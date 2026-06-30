# Advisory: Insider Abuse of Valid Accounts

> **REPRESENTATIVE / ILLUSTRATIVE sample.** Curated for the Prahari demo from
> public MITRE ATT&CK technique descriptions (T1078) and CERT-In public guidance
> ("Guidelines on Information Security Practices for Government Entities"). Not a
> verbatim CERT-In advisory; replace with the live CERT-In feed in production.

**Summary.** A trusted insider — or an adversary using stolen-but-valid
credentials — operates within their existing access rather than exploiting a
vulnerability. Because the account is legitimate, signature and perimeter
controls do not fire; the abuse is visible only as a deviation from the user's
normal behaviour. Government entities holding citizen records are a high-value
target for such valid-account abuse.

**Observed behaviour.** A user authenticating to systems they have rights to but
never normally use (e.g. an analyst logging directly into a database server),
frequently at off-hours, with no failed-logon noise and no malware. New
user→host pairings and off-hours access are the strongest tells.

**Recommended detections.** Baseline each account's normal hosts, hours, and data
scope; alert on first-seen user→host pairings, off-hours access to sensitive
servers, and access that exceeds the role's normal data footprint. Enforce MFA
and least privilege; review standing access to crown-jewel data.

**Mapping.** Defense-evasion / persistence / initial-access via Valid Accounts.
