#!/usr/bin/env python3
import argparse
import http.client
import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Iterable, List, Optional, Tuple

ADMIN_PORTS = (82, 83, 443, 8080, 8443, 9443)
QUARANTINE_PORTS = (6025, 82, 83, 8443, 9443)
SPAM_PATHS = ("/quarantine", "/spamquarantine", "/spam", "/sma-login", "/login")
BODY_KEYWORDS = (
    "cisco secure email",
    "secure email and web manager",
    "secure email gateway",
    "spam quarantine",
    "quarantine login",
    "asyncos",
    "ironport",
)
VERSION_PATTERNS = (
    r"asyncos[^\d]*(\d+\.\d+\.\d+)",
    r"version[:\s]+(\d+\.\d+\.\d+)",
)


def vprint(verbose: bool, message: str) -> None:
    if verbose:
        print(message)


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


def scan_ports(
    host: str, ports: Iterable[int], timeout: float = 3.0, max_workers: int = 10, verbose: bool = False
) -> List[int]:
    unique_ports = sorted(set(int(p) for p in ports))
    if not unique_ports:
        return []

    worker_count = max(1, min(max_workers, len(unique_ports)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {executor.submit(is_port_open, host, port, timeout): port for port in unique_ports}
        open_ports: List[int] = []
        for future, port in futures.items():
            is_open = future.result()
            vprint(verbose, f"  - Port {port} {'open' if is_open else 'closed'}")
            if is_open:
                open_ports.append(port)
        return open_ports


def probe_http_banner(host: str, port: int, timeout: float = 3.0) -> Dict[str, Optional[str]]:
    """Best-effort HTTP/HTTPS probe for lightweight fingerprinting."""

    def _attempt(scheme: str) -> Dict[str, Optional[str]]:
        conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        context = ssl._create_unverified_context() if scheme == "https" else None
        try:
            conn = conn_cls(host, port, timeout=timeout, context=context) if context else conn_cls(host, port, timeout=timeout)
            conn.request("GET", "/", headers={"User-Agent": "cisco-sma-exposure-check"})
            resp = conn.getresponse()
            body = resp.read(2048)  # keep it small
            headers = {k.lower(): v for k, v in resp.getheaders()}
            conn.close()
            body_text = body.decode(errors="ignore")
            lower_body = body_text.lower()
            version = None
            for pattern in VERSION_PATTERNS:
                match = re.search(pattern, body_text, flags=re.IGNORECASE)
                if match:
                    version = match.group(1)
                    break
            indicators = [
                kw
                for kw in BODY_KEYWORDS
                if kw in lower_body
                or (headers.get("server") and kw in headers["server"].lower())
                or (headers.get("www-authenticate") and kw in headers["www-authenticate"].lower())
            ]
            return {
                "scheme": scheme,
                "status": f"{resp.status} {resp.reason}",
                "server": headers.get("server"),
                "location": headers.get("location"),
                "www_authenticate": headers.get("www-authenticate"),
                "indicators": ", ".join(sorted(set(indicators))) or None,
                "version": version,
                "error": None,
            }
        except (ssl.SSLError, OSError) as exc:
            return {
                "scheme": scheme,
                "status": None,
                "server": None,
                "location": None,
                "www_authenticate": None,
                "indicators": None,
                "version": None,
                "error": str(exc),
            }

    https_result = _attempt("https")
    if https_result["error"] is None:
        return https_result

    http_result = _attempt("http")
    if http_result["error"] is None:
        return http_result

    # Neither HTTPS nor HTTP responded cleanly; return the HTTPS error by default.
    return https_result


def probe_quarantine_paths(
    host: str, port: int, scheme: str, timeout: float = 3.0, verbose: bool = False
) -> List[Dict[str, Optional[str]]]:
    """Probe common quarantine paths for indicative responses."""
    hits: List[Dict[str, Optional[str]]] = []

    def _scan(scheme_to_use: str) -> None:
        conn_cls = http.client.HTTPSConnection if scheme_to_use == "https" else http.client.HTTPConnection
        context = ssl._create_unverified_context() if scheme_to_use == "https" else None

        for path in SPAM_PATHS:
            try:
                conn = (
                    conn_cls(host, port, timeout=timeout, context=context)
                    if context
                    else conn_cls(host, port, timeout=timeout)
                )
                conn.request("GET", path, headers={"User-Agent": "cisco-sma-exposure-check"})
                resp = conn.getresponse()
                body = resp.read(1024)
                headers = {k.lower(): v for k, v in resp.getheaders()}
                conn.close()
            except (ssl.SSLError, OSError) as exc:
                vprint(verbose, f"    - {scheme_to_use}://{host}:{port}{path} probe failed: {exc}")
                continue

            lower_body = body.decode(errors="ignore").lower()
            kw_hit = any(keyword in lower_body for keyword in ("quarantine", "spam", "cisco", "ironport", "asyncos"))
            vprint(
                verbose,
                f"    - {scheme_to_use}://{host}:{port}{path} -> {resp.status} "
                f"{resp.reason}{' (keywords found)' if kw_hit else ''}",
            )
            if resp.status in (200, 301, 302, 401) and kw_hit:
                hits.append(
                    {
                        "scheme": scheme_to_use,
                        "path": path,
                        "status": f"{resp.status} {resp.reason}",
                        "location": headers.get("location"),
                        "www_authenticate": headers.get("www-authenticate"),
                    }
                )
                if len(hits) >= 3:
                    return

    _scan(scheme)
    if not hits and scheme == "https":
        _scan("http")
    return hits


def grab_raw_banner(host: str, port: int, timeout: float = 3.0) -> Dict[str, Optional[str]]:
    """Grab a simple banner over a raw socket."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
            sock.sendall(request)
            data = sock.recv(1024)
            return {"banner": data.decode(errors="ignore").strip(), "error": None}
    except OSError as exc:
        return {"banner": None, "error": str(exc)}


def assess_risk(target: str, timeout: float = 3.0, verbose: bool = False) -> bool:
    host, resolved_ip = resolve_target(target)
    print(
        f"Scanning {host} (resolved to {resolved_ip}) for Cisco Secure Email/SMA exposure (CVE-2025-20393)..."
    )

    vprint(verbose, f"- Checking admin ports: {', '.join(str(p) for p in ADMIN_PORTS)}")
    admin_ports = scan_ports(resolved_ip, ADMIN_PORTS, timeout=timeout, verbose=verbose)
    vprint(verbose, f"- Checking quarantine ports: {', '.join(str(p) for p in QUARANTINE_PORTS)}")
    quarantine_ports = scan_ports(resolved_ip, QUARANTINE_PORTS, timeout=timeout, verbose=verbose)

    print("\nAdmin/Management ports open:", admin_ports or "None")
    print("Spam Quarantine ports open:", quarantine_ports or "None")

    open_ports = sorted(set(admin_ports + quarantine_ports))
    quarantine_paths_found = False
    cisco_indicators_found = False
    if not open_ports:
        vprint(verbose, "No open admin or quarantine ports found; skipping HTTP/S banner and quarantine path probes.")
    if open_ports:
        print("\nHTTP/S fingerprints (best effort):")
        for port in open_ports:
            vprint(verbose, f"  > Probing HTTP/HTTPS on port {port}")
            banner = probe_http_banner(resolved_ip, port, timeout=timeout)
            if banner["error"]:
                print(f"- {port}/tcp: no HTTP banner ({banner['error']})")
                raw_banner = grab_raw_banner(resolved_ip, port, timeout=timeout)
                if raw_banner["banner"]:
                    first_line = raw_banner["banner"].splitlines()[0] if raw_banner["banner"] else ""
                    print(f"  -> Raw banner: {first_line}")
                elif verbose:
                    print(f"  -> Raw banner grab failed: {raw_banner['error']}")
                continue
            summary = f"- {port}/{banner['scheme']}: {banner['status']}"
            if banner["server"]:
                summary += f" | Server: {banner['server']}"
            if banner["location"]:
                summary += f" | Location: {banner['location']}"
            if banner["www_authenticate"]:
                summary += f" | Auth: {banner['www_authenticate']}"
            if banner["indicators"]:
                summary += f" | Indicators: {banner['indicators']}"
                cisco_indicators_found = True
            if banner["version"]:
                summary += f" | Version: {banner['version']}"
                cisco_indicators_found = True
            print(summary)
            raw_banner = grab_raw_banner(resolved_ip, port, timeout=timeout)
            if raw_banner["banner"]:
                first_line = raw_banner["banner"].splitlines()[0] if raw_banner["banner"] else ""
                print(f"  -> Raw banner: {first_line}")
            elif verbose:
                print(f"  -> Raw banner grab failed: {raw_banner['error']}")
            hits = probe_quarantine_paths(resolved_ip, port, banner["scheme"], timeout=timeout, verbose=verbose)
            for hit in hits:
                quarantine_paths_found = True
                detail = f"  -> {port}/{hit['scheme']}{hit['path']}: {hit['status']}"
                if hit["location"]:
                    detail += f" | Location: {hit['location']}"
                if hit["www_authenticate"]:
                    detail += f" | Auth: {hit['www_authenticate']}"
                print(detail)
            if verbose and not hits:
                print("  -> Quarantine path probes: no indicative responses")

    # Only report exposure if we found Cisco-specific indicators
    is_exposed = cisco_indicators_found or quarantine_paths_found
    
    if is_exposed:
        print("\n" + "=" * 60)
        print("POTENTIAL CISCO SECURE EMAIL/SMA EXPOSURE DETECTED")
        print("=" * 60)
        if cisco_indicators_found:
            print("- Cisco-specific indicators found in HTTP responses")
        if quarantine_paths_found:
            print("- Quarantine login paths responded with Cisco keywords")
        if 6025 in quarantine_ports:
            print("- Port 6025 open (spam quarantine) - high risk indicator")
        print("\nRecommended actions:")
        print("1) Block internet access to these ports")
        print("2) Disable Spam Quarantine or restrict access")
        print(
            "3) Review Cisco advisory: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sma-attack-N9bf4"
        )
        return True
    
    # Special case: port 6025 is almost always Cisco spam quarantine
    if 6025 in quarantine_ports:
        print("\n" + "=" * 60)
        print("WARNING: PORT 6025 OPEN")
        print("=" * 60)
        print("Port 6025 is commonly used for Cisco Spam Quarantine.")
        print("Even without confirmed indicators, this warrants investigation.")
        print("\nRecommended: Verify if this is a Cisco appliance and restrict access.")
        return True

    print("\n" + "=" * 60)
    print("RESULT: NO EXPOSURE DETECTED")
    print("=" * 60)
    print(f"Target: {host} ({resolved_ip})")
    print("- No admin/management ports open")
    print("- No spam quarantine ports open")
    print("\nThis host does not appear to expose Cisco Secure Email/SMA")
    print("management interfaces to the scanned network.")
    return False


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Quick external exposure check for Cisco Secure Email/SMA (CVE-2025-20393).",
    )
    parser.add_argument("target", help="Target host or domain")
    parser.add_argument("-t", "--timeout", type=float, default=3.0, help="Connection timeout in seconds (default: 3)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all checks performed")

    args = parser.parse_args(argv)
    try:
        assess_risk(args.target, timeout=args.timeout, verbose=args.verbose)
    except ValueError as exc:
        print(exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
