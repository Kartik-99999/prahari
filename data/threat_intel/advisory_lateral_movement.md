# Advisory: Lateral Movement over RDP/SMB with Valid Accounts

> **REPRESENTATIVE / ILLUSTRATIVE sample.** Synthetic CERT-In-style advisory for
> the Prahari demo. Replace with the live CERT-In feed in production.

**Summary.** Using credentials harvested from a compromised host, adversaries
authenticate to remote services — Remote Desktop (RDP/3389) and SMB/Windows
Admin Shares (445) — to move laterally toward high-value systems such as domain
controllers and database servers. Movement is often slow and conducted in the
dead of night to avoid notice.

**Observed behaviour.** New host-to-host logons that the account has never made
before (new user→host pairings), interactive RDP sessions and SMB connections
between internal hosts at off-hours, forming a chain workstation → domain
controller → database server.

**Recommended detections.** Correlate authentications across hosts; flag new
source→destination host pairs, off-hours RDP/SMB, and admin logons to servers
that the account does not normally touch.

**Mapping.** Lateral Movement via remote services using valid accounts.
