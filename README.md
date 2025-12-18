# Cisco SMA Exposure Check

Small, single-file Python 3 script to quickly probe a host or domain for open Cisco Secure Email/Secure Malware Analytics management and quarantine ports (CVE-2025-20393 exposure indicators).

## Usage
- Install Python 3 (stdlib only; no extra dependencies).
- Run the scanner:
  ```bash
  python3 cisco-sa-sma-attack-N9bf4.py [-v] [-t <timeout-seconds>] <host-or-domain>
  ```
- The script resolves the target to its first IP, reports any open admin ports (82, 83, 443, 8080, 8443, 9443) and spam quarantine ports (6025, 82, 83, 8443, 9443), performs a lightweight HTTP/S fingerprint on open ports (server header, status, redirects, auth realm, Cisco keywords, version patterns), probes common spam quarantine paths (/quarantine, /spamquarantine, /spam, /sma-login, /login), grabs a raw socket banner, and highlights basic IOC strings (AquaShell, AquaTunnel, Chisel, AquaPurge patterns) if seen. Use `-v` to show all checks performed.

## Notes
- Provide an IP directly if you want to bypass DNS resolution.
- Use responsibly and only against systems you are authorized to test.
