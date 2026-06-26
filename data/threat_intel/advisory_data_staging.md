# Advisory: Data Staging and Archiving Prior to Exfiltration

> **REPRESENTATIVE / ILLUSTRATIVE sample.** Synthetic CERT-In-style advisory for
> the Prahari demo. Replace with the live CERT-In feed in production.

**Summary.** Before exfiltration, adversaries collect sensitive records from a
target data store and compress them into a single archive to reduce volume and
evade content inspection. On database servers this often means dumping records
and packing them with `7z`, `rar`, or `tar` into a temp/staging directory.

**Observed behaviour.** Archive utilities (`7z.exe`, `rar.exe`) executed on a
database/file server against sensitive data, producing a large archive file
(e.g. `/tmp/exam-records.7z`) at an unusual hour, by an account not normally
running such tools there.

**Recommended detections.** Monitor archive-tool execution on servers holding
sensitive data and creation of large archives in staging directories.

**Mapping.** Collection via archiving collected data (and data from local
system / databases).
