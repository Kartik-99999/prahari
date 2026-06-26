# Advisory: OS Credential Dumping via LSASS Memory Access

> **REPRESENTATIVE / ILLUSTRATIVE sample.** Synthetic CERT-In-style advisory for
> the Prahari demo. Replace with the live CERT-In feed in production.

**Summary.** After gaining a foothold, adversaries dump operating-system
credentials by reading the memory of the Local Security Authority Subsystem
Service (LSASS). Tooling includes `rundll32.exe comsvcs.dll, MiniDump`,
`procdump`, and Mimikatz. Harvested hashes and tickets enable privilege
escalation and lateral movement under valid accounts.

**Observed behaviour.** A process opening a handle to `lsass.exe` and writing a
memory dump file (e.g. `out.dmp`) to a temp directory, frequently at off-hours
on a recently-compromised workstation.

**Recommended detections.** Monitor LSASS access, `comsvcs.dll MiniDump`
command lines, and creation of `.dmp` files in `C:\Windows\Temp`.

**Mapping.** Credential Access via OS credential dumping.
