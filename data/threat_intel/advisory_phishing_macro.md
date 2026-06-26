# Advisory: Spear-Phishing with Malicious Office Macros

> **REPRESENTATIVE / ILLUSTRATIVE sample.** This is a synthetic CERT-In-style
> advisory written for the Prahari demo. Swap for the live CERT-In feed
> (cert-in.org.in) and commercial threat-intel in production.

**Summary.** A spear-phishing campaign delivers Microsoft Office documents
carrying malicious VBA macros. When the recipient enables content, the macro
spawns a scripting interpreter (commonly `powershell.exe`) as a child of
`winword.exe`/`excel.exe`, which then reaches out to an attacker-controlled host
to download a second-stage implant and establish a foothold.

**Observed behaviour.** Office application spawning PowerShell with an encoded
(`-enc`) command; immediate outbound TLS connection to a previously-unseen
external IP shortly after a document is opened during business hours.

**Recommended detections.** Alert on office-app → interpreter process lineage,
encoded PowerShell, and new external destinations for a workstation.

**Mapping.** Initial Access via phishing; execution via command interpreter;
follow-on command-and-control.
