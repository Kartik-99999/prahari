# Advisory: Data Exfiltration over the C2 Channel

> **REPRESENTATIVE / ILLUSTRATIVE sample.** Synthetic CERT-In-style advisory for
> the Prahari demo. Replace with the live CERT-In feed in production.

**Summary.** In the final stage of an intrusion, adversaries steal the staged
archive by exfiltrating it over the already-established command-and-control
channel, encoding stolen data within normal-looking C2 traffic to the external
controller. Exfiltration from a database/file server to an external IP is a
high-severity, late-stage indicator that the breach is completing.

**Observed behaviour.** Large or anomalous outbound transfers from a server
holding sensitive data to an external destination on 443, correlating with
prior C2 beaconing, often at off-hours and in multiple chunks.

**Recommended detections.** Alert on outbound data volume anomalies from
sensitive servers, egress to known C2 destinations, and exfil that follows a
staging/archiving event.

**Mapping.** Exfiltration over the C2 channel.
