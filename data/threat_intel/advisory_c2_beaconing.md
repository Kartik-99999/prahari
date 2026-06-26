# Advisory: Command-and-Control Beaconing over HTTPS

> **REPRESENTATIVE / ILLUSTRATIVE sample.** Synthetic CERT-In-style advisory for
> the Prahari demo. Replace with the live CERT-In feed in production.

**Summary.** Implants maintain contact with attacker infrastructure by beaconing
over common application-layer protocols (HTTP/HTTPS on 443, sometimes DNS) so
that malicious traffic blends with normal web traffic. The beacon periodically
checks in to an external controller and receives tasking.

**Observed behaviour.** Periodic outbound TLS connections from a workstation to
a rare external IP on 443, originating from a host/process that does not
normally communicate with the internet (e.g. immediately after a phishing
payload executes).

**Recommended detections.** Hunt for beaconing periodicity, connections to
low-reputation/previously-unseen external destinations, and egress from hosts
that should not initiate internet traffic.

**Mapping.** Command-and-Control via application-layer protocol.
