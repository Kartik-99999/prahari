# Advisory: Detecting Low-and-Slow Insider Data Theft

> **REPRESENTATIVE / ILLUSTRATIVE sample.** Curated for the Prahari demo from
> public MITRE ATT&CK (T1078/T1087/T1005/T1074/T1560/T1052) and CERT-In public
> guidance ("Guidelines on Information Security Practices for Government
> Entities"). Not a verbatim CERT-In advisory; replace with the live CERT-In
> feed in production.

**Summary.** The most damaging insider campaigns are patient: a trusted user
spends weeks quietly collecting a sensitive dataset, then exfiltrates it without
ever touching the internet. The full chain is access (valid accounts) →
discovery → low-and-slow collection → staging → archive → physical/USB exfil.
No single event is alarming; the campaign is visible only when weak behavioural
signals are correlated across entities and time.

**Observed behaviour.** Off-hours access to a sensitive server the user does not
normally use; broad enumeration; repeated bulk reads below volume thresholds;
staging to a share; an archiver (`7z`, `rar`) on the staging host; finally a
write to removable media — all by one identity, with no external destination.

**Recommended detections.** Behavioural baselining (per-user host/hour/data
scope), entity-and-time correlation of weak signals into a single incident,
and device-control on crown-jewel hosts. Treat new-user→host pairings,
off-hours access, rare processes, and removable-media writes as corroborating
weak signals rather than standalone alerts.

**Mapping.** Insider exfiltration kill chain (collection → exfiltration).
