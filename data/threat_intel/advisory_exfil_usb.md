# Advisory: Exfiltration Over Physical Medium (USB)

> **REPRESENTATIVE / ILLUSTRATIVE sample.** Curated for the Prahari demo from
> public MITRE ATT&CK technique descriptions (T1052, incl. T1052.001 USB) and
> CERT-In public guidance. Not a verbatim CERT-In advisory; replace with the live
> CERT-In feed in production.

**Summary.** When network egress is monitored or blocked, an insider can defeat
all perimeter DLP by simply copying the staged archive to a removable USB drive
and walking it out. There is NO external connection to detect — the only signal
is a write of a large/sensitive archive to a removable-media path.

**Observed behaviour.** A file write to a removable drive (e.g. `E:\...`,
`/media/...`) of an archive that was just assembled from sensitive data, often
off-hours, with no preceding or following network egress. The absence of C2 or
external transfer is itself characteristic of the physical-medium path.

**Recommended detections.** Monitor removable-media mounts and writes; alert on
archives of sensitive data being copied to removable media; enforce USB
device-control policy on hosts with access to crown-jewel data. Correlate with
prior staging/archiving (T1074/T1560) on the same host/user.

**Mapping.** Exfiltration Over Physical Medium (removable USB).
