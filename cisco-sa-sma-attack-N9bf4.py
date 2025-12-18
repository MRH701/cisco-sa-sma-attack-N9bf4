#!/usr/bin/env python3
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, List, Tuple

ADMIN_PORTS = (82, 83, 443, 8080)
QUARANTINE_PORTS = (6025, 82, 83)


def resolve_target(target: str) -> Tuple[str, str]:
    """Return the original target and the first resolved IP address."""
    host = target.strip()
    if not host:
        raise ValueError("Target cannot be empty")

    try:
        addrinfo = socket.getaddrinfo(host, None)[0]
        return host, addrinfo[4][0]
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve {host}: {exc}") from exc


def is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ports(host: str, ports: Iterable[int], timeout: float = 3.0, max_workers: int = 10) -> List[int]:
    unique_ports = sorted(set(int(p) for p in ports))
    if not unique_ports:
        return []

    worker_count = max(1, min(max_workers, len(unique_ports)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {executor.submit(is_port_open, host, port, timeout): port for port in unique_ports}
        return [port for future, port in futures.items() if future.result()]


def assess_risk(target: str, timeout: float = 3.0) -> bool:
    host, resolved_ip = resolve_target(target)
    print(
        f"Scanning {host} (resolved to {resolved_ip}) for Cisco Secure Email/SMA exposure (CVE-2025-20393)..."
    )

    admin_ports = scan_ports(resolved_ip, ADMIN_PORTS, timeout=timeout)
    quarantine_ports = scan_ports(resolved_ip, QUARANTINE_PORTS, timeout=timeout)

    print("\nAdmin/Management ports open:", admin_ports or "None")
    print("Spam Quarantine ports open:", quarantine_ports or "None")

    if admin_ports or quarantine_ports:
        print("\nPOTENTIAL EXPOSURE DETECTED")
        print("- Open admin ports may expose administrator identifiers")
        print("- Open quarantine ports (especially 6025) indicate risky configuration [web:21][web:7]")
        print("\nRecommended actions:")
        print("1) Block internet access to these ports")
        print("2) Disable Spam Quarantine or restrict access")
        print(
            "3) Review Cisco advisory: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sma-attack-N9bf4 [web:1]"
        )
        return True

    print("\nNo immediate exposure indicators found")
    return False


def main(argv: List[str]) -> int:
    if len(argv) != 1:
        print("Usage: python3 cisco-sa-sma-attack-N9bf4.py <host-or-domain>")
        return 1

    target = argv[0]
    try:
        assess_risk(target)
    except ValueError as exc:
        print(exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
