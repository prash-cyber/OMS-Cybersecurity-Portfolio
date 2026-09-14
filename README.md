# Security Investigation Projects

A collection of hands-on security investigation write-ups. Each project works through a real dataset or CTF-style scenario using industry-standard tools, documenting the questions asked, the queries used to answer them, and the reasoning behind each step.

## Projects

| # | Project | Tools | Summary |
|---|---------|-------|---------|
| 1 | [Splunk – Frothly Incident Investigation](./Security Operations & Incident Response/Project 1 - Splunk/Project 1 - Splunk.md) | Splunk, SPL, VirusTotal, Broadcom/Symantec | Investigates an AWS console compromise, a publicly exposed S3 bucket, a cryptomining malware infection, and a leaked AWS access key using the BOTS v3 (Boss of the SOC) dataset. |
| 2 | [Man In The Middle](./Information Security/Project 2 - MITM/Project 2 - Man-In-The-Middle.md) | Wireshark, GPG, dig/curl/wget, John the Ripper | Reconstructs an IRC threat actor's chat log from a packet capture, decrypts a PGP-protected file transfer, fingerprints the domain behind it, pulls FTP credentials and a payload off a compromised server, and cracks a password-protected zip to reach the final flag. |

*More projects will be added here as they're completed.*

## Skills demonstrated

- Log analysis and SPL query writing (Splunk)
- Network traffic analysis and protocol reconstruction (Wireshark)
- Incident investigation and timeline reconstruction
- Cloud security (AWS IAM, S3 misconfigurations)
- Cryptography (PGP/GPG, password cracking with John the Ripper)
- Malware/threat triage using external intel sources (VirusTotal, Broadcom/Symantec)
