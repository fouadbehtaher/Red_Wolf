"""Fail-closed host allowlists for explicitly authorized scan targets."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _normalize_host(value: str) -> str:
    host = value.strip().rstrip(".").lower()
    if not host:
        raise ValueError("Host cannot be empty.")
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        pass

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid hostname: {value}") from exc
    if len(ascii_host) > 253 or any(
        not _DOMAIN_LABEL.fullmatch(label) for label in ascii_host.split(".")
    ):
        raise ValueError(f"Invalid hostname: {value}")
    return ascii_host


def _host_from_target(target: str) -> str:
    target = target.strip()
    if "://" not in target:
        target = f"https://{target}"
    try:
        parsed = urlsplit(target)
        host = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid target URL: {target}") from exc
    if not host:
        raise ValueError(f"Invalid target URL: {target}")
    return _normalize_host(host)


def _matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith(f".{base}")
    return host == pattern


@dataclass(frozen=True)
class ScopePolicy:
    """A host allowlist where explicit exclusions override all inclusions."""

    included: tuple[str, ...]
    excluded: tuple[str, ...]

    @classmethod
    def from_file(cls, path: str | Path) -> "ScopePolicy":
        included: list[str] = []
        excluded: list[str] = []
        for line_number, raw_line in enumerate(
            Path(path).read_text(encoding="utf-8-sig").splitlines(), 1
        ):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            is_excluded = line.startswith("!")
            pattern = line[1:].strip() if is_excluded else line
            wildcard = pattern.startswith("*.")
            host_part = pattern[2:] if wildcard else pattern
            if not host_part or "*" in host_part or "://" in host_part or any(
                char in host_part for char in "/:@?#"
            ):
                raise ValueError(f"Invalid scope entry on line {line_number}: {raw_line}")
            try:
                normalized = _normalize_host(host_part)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid scope entry on line {line_number}: {raw_line}"
                ) from exc
            if wildcard:
                try:
                    ipaddress.ip_address(normalized)
                except ValueError:
                    pass
                else:
                    raise ValueError(
                        f"Wildcard scope entries must use a domain on line {line_number}."
                    )
            normalized_pattern = f"*.{normalized}" if wildcard else normalized
            (excluded if is_excluded else included).append(normalized_pattern)

        if not included:
            raise ValueError("Scope file must contain at least one included host.")
        return cls(tuple(included), tuple(excluded))

    def permits(self, target: str) -> bool:
        host = _host_from_target(target)
        if any(_matches(pattern, host) for pattern in self.excluded):
            return False
        return any(_matches(pattern, host) for pattern in self.included)

    def filter_targets(self, targets: list[str]) -> tuple[list[str], list[str]]:
        allowed: list[str] = []
        rejected: list[str] = []
        for target in targets:
            (allowed if self.permits(target) else rejected).append(target)
        return allowed, rejected
