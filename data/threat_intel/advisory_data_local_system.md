# Advisory: Bulk Collection of Data from Local Systems

> **REPRESENTATIVE / ILLUSTRATIVE sample.** Curated for the Prahari demo from
> public MITRE ATT&CK technique descriptions (T1005, T1213) and CERT-In public
> guidance. Not a verbatim CERT-In advisory; replace with the live CERT-In feed
> in production.

**Summary.** Having located the target, the actor reads sensitive data directly
from the server or database that holds it. Insiders typically perform this "low
and slow" — a few files per night over weeks — to stay under volume-based
alerting while assembling a complete copy of, e.g., an exam-records or citizen
database.

**Observed behaviour.** Repeated reads of sensitive record files by one user on
one server, clustered at off-hours, far exceeding that user's historical access
rate, often with no corresponding business transaction. The first read of each
new file/host is the strongest novelty signal; later reads in the same session
are weaker and easily missed by per-event scoring alone.

**Recommended detections.** Baseline per-user data-access rate and scope; alert
on access volume/scope anomalies on sensitive stores, especially off-hours.
Correlate the weak repeated-read signals across the campaign window rather than
scoring each read in isolation.

**Mapping.** Collection of Data from Local System / Information Repositories.
