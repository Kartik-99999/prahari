# Advisory: Account and Directory Discovery

> **REPRESENTATIVE / ILLUSTRATIVE sample.** Curated for the Prahari demo from
> public MITRE ATT&CK technique descriptions (T1087, T1083) and CERT-In public
> guidance. Not a verbatim CERT-In advisory; replace with the live CERT-In feed
> in production.

**Summary.** Before collecting data, an actor enumerates the environment to find
what is worth taking and who has access — listing domain accounts, group
memberships, shares, and directory trees. For an insider this often looks like
unusually broad "looking around" on a server they rarely touch.

**Observed behaviour.** Built-in tooling run interactively at odd hours:
`net group/​user /domain`, `dir /s` over a records share, `whoami /groups`,
directory listings of sensitive paths. Individually benign, but anomalous when
run by a user/host that never normally performs enumeration.

**Recommended detections.** Alert on enumeration commands executed by
non-administrative users, recursive listing of sensitive shares, and discovery
activity immediately preceding bulk file access. Correlate with off-hours and
new-process-on-host signals.

**Mapping.** Discovery via Account/Permission/Directory enumeration.
