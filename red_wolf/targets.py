"""Target expansion helpers for URLs, CIDR ranges, and wildcard domains."""

import ipaddress
import socket
from typing import List, Tuple
from urllib.parse import urlparse


MAX_EXPANDED_TARGETS = 256
COMMON_SUBDOMAIN_LABELS = (
    "www", "api", "admin", "app", "portal", "dev", "staging", "test",
    "qa", "uat", "beta", "mail", "vpn", "remote", "auth", "login",
    "cdn", "static", "assets", "files", "download", "docs", "status",
)


def expand_target(value: str, max_targets: int = MAX_EXPANDED_TARGETS) -> Tuple[List[str], str]:
    """Expand one user target locally and return targets plus a warning."""
    value = value.strip()
    if not value:
        raise ValueError("Target cannot be empty.")

    raw_host = value.split("://", 1)[-1]
    try:
        network = ipaddress.ip_network(raw_host, strict=False)
    except ValueError:
        network = None

    parsed = urlparse(value if "://" in value else f"https://{value}")
    scheme = parsed.scheme or "https"
    host = parsed.hostname
    if not host:
        raise ValueError(f"Invalid target: {value}")

    if network:
        hosts = list(network.hosts())
        warning = ""
        if len(hosts) > max_targets:
            warning = (
                f"CIDR contains {len(hosts)} hosts; limiting this scan to "
                f"the first {max_targets} hosts."
            )
            hosts = hosts[:max_targets]
        return [f"{scheme}://{address}" for address in hosts], warning

    if host.startswith("*."):
        domain = host[2:]
        candidates = [domain] + [f"{label}.{domain}" for label in COMMON_SUBDOMAIN_LABELS]
        resolved = []
        for candidate in candidates:
            try:
                socket.getaddrinfo(candidate, parsed.port or (443 if scheme == "https" else 80))
            except socket.gaierror:
                continue
            resolved.append(f"{scheme}://{candidate}")
        warning = (
            f"Wildcard expansion checked {len(candidates) - 1} common subdomain "
            f"labels locally and found {len(resolved)} resolvable target(s). "
            "Use --endpoints-file for a complete authorized inventory."
        )
        return resolved[:max_targets], warning

    base = value.rstrip("/")
    if "://" not in value:
        base = f"{scheme}://{base}"
    return [base], ""
