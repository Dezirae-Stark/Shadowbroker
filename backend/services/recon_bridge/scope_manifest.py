"""Scope manifest — the authorization backbone for the recon bridge.

Schema: docs/superpowers/specs/2026-05-05-shadowbroker-integration-design.md §7.

Validation order (matters!):
  1. expired? → reject
  2. matches exclude? → reject (exclusions ALWAYS win)
  3. mode == lab and matches region_lock? → accept
  4. matches include? → accept
  5. otherwise → reject
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

import yaml


KNOWN_MODES = {"engagement", "bounty", "self", "lab"}
KNOWN_TOP_LEVEL_FIELDS = {
    "version",
    "manifest_id",
    "mode",
    "created_at",
    "expires_at",
    "authorization",
    "targets",
    "bounty",
    "lab",
}


class ScopeManifestError(Exception):
    pass


@dataclass(frozen=True)
class Target:
    kind: str  # "url" | "ip" | "cidr" | "asn"
    value: str


@dataclass(frozen=True)
class ScopeResult:
    in_scope: bool
    reason: str
    manifest_id: str = ""
    mode: str = ""


@dataclass
class ScopeManifest:
    manifest_id: str
    mode: str
    expires_at: datetime
    include_domains: list[str] = field(default_factory=list)
    include_cidrs: list[ipaddress._BaseNetwork] = field(default_factory=list)
    include_asns: list[str] = field(default_factory=list)
    exclude_domains: list[str] = field(default_factory=list)
    exclude_cidrs: list[ipaddress._BaseNetwork] = field(default_factory=list)
    lab_region_lock: Optional[ipaddress._BaseNetwork] = None

    @classmethod
    def from_dict(cls, data: dict) -> "ScopeManifest":
        unknown = set(data.keys()) - KNOWN_TOP_LEVEL_FIELDS
        if unknown:
            raise ScopeManifestError(f"unknown field(s): {sorted(unknown)}")

        if "expires_at" not in data:
            raise ScopeManifestError("expires_at is required")

        mode = data.get("mode")
        if mode not in KNOWN_MODES:
            raise ScopeManifestError(
                f"unknown mode: {mode!r}; allowed: {sorted(KNOWN_MODES)}"
            )

        targets = data.get("targets", {}) or {}
        include = targets.get("include") or {}
        exclude = targets.get("exclude") or {}

        lab_region_lock = None
        if mode == "lab":
            lab = data.get("lab") or {}
            rl = lab.get("region_lock")
            if rl:
                lab_region_lock = ipaddress.ip_network(rl, strict=False)

        return cls(
            manifest_id=data["manifest_id"],
            mode=mode,
            expires_at=_parse_iso(data["expires_at"]),
            include_domains=list(include.get("domains") or []),
            include_cidrs=[
                ipaddress.ip_network(c, strict=False)
                for c in (include.get("ip_cidrs") or [])
            ],
            include_asns=[_normalize_asn(a) for a in (include.get("asns") or [])],
            exclude_domains=list(exclude.get("domains") or []),
            exclude_cidrs=[
                ipaddress.ip_network(c, strict=False)
                for c in (exclude.get("ip_cidrs") or [])
            ],
            lab_region_lock=lab_region_lock,
        )

    def validate(
        self, target: Target, *, now: Callable[[], float] = time.time
    ) -> ScopeResult:
        # Rule 1: expired?
        if self.expires_at.timestamp() < now():
            return ScopeResult(
                in_scope=False,
                reason=f"manifest {self.manifest_id} expired at {self.expires_at.isoformat()}",
                manifest_id=self.manifest_id,
                mode=self.mode,
            )

        host_or_ip, error = _resolve_target_for_match(target)
        if error:
            return ScopeResult(
                in_scope=False,
                reason=error,
                manifest_id=self.manifest_id,
                mode=self.mode,
            )

        # Rule 2: excluded? (always wins)
        if target.kind == "url" and host_or_ip:
            for pattern in self.exclude_domains:
                if _domain_match(host_or_ip, pattern):
                    return ScopeResult(
                        False,
                        f"excluded by domain pattern {pattern}",
                        self.manifest_id,
                        self.mode,
                    )
        if target.kind == "ip":
            try:
                ip = ipaddress.ip_address(host_or_ip)
                for net in self.exclude_cidrs:
                    if ip in net:
                        return ScopeResult(
                            False,
                            f"excluded by cidr {net}",
                            self.manifest_id,
                            self.mode,
                        )
            except ValueError:
                pass
        if target.kind == "cidr":
            # ANY overlap with an exclude_cidr rejects — operators must not
            # be able to scope-check a network that contains excluded hosts.
            # Codex R2 P2: mirror of the deep-eye round-1 fix on the server.
            try:
                requested = ipaddress.ip_network(host_or_ip, strict=False)
                for net in self.exclude_cidrs:
                    if requested.overlaps(net):
                        return ScopeResult(
                            False,
                            f"overlaps excluded cidr {net}",
                            self.manifest_id,
                            self.mode,
                        )
            except ValueError:
                pass

        # Rule 3: lab mode region_lock
        if self.mode == "lab" and self.lab_region_lock is not None:
            if target.kind == "ip":
                try:
                    if ipaddress.ip_address(host_or_ip) in self.lab_region_lock:
                        return ScopeResult(
                            True,
                            f"lab region_lock match {self.lab_region_lock}",
                            self.manifest_id,
                            self.mode,
                        )
                    return ScopeResult(
                        False,
                        f"outside lab region_lock {self.lab_region_lock}",
                        self.manifest_id,
                        self.mode,
                    )
                except ValueError:
                    pass

        # Rule 4: include match
        if target.kind == "url" and host_or_ip:
            for pattern in self.include_domains:
                if _domain_match(host_or_ip, pattern):
                    return ScopeResult(
                        True,
                        f"matched domain pattern {pattern}",
                        self.manifest_id,
                        self.mode,
                    )
        if target.kind == "ip":
            try:
                ip = ipaddress.ip_address(host_or_ip)
                for net in self.include_cidrs:
                    if ip in net:
                        return ScopeResult(
                            True,
                            f"matched cidr {net}",
                            self.manifest_id,
                            self.mode,
                        )
            except ValueError:
                pass
        if target.kind == "cidr":
            # The requested CIDR must be a subnet of an include_cidr —
            # i.e. fully contained, no hosts outside what was authorized.
            try:
                requested = ipaddress.ip_network(host_or_ip, strict=False)
                for net in self.include_cidrs:
                    if requested.subnet_of(net):
                        return ScopeResult(
                            True,
                            f"cidr {requested} subnet of include cidr {net}",
                            self.manifest_id,
                            self.mode,
                        )
            except ValueError:
                pass
        if target.kind == "asn":
            normalized = _normalize_asn(target.value)
            if normalized in self.include_asns:
                return ScopeResult(
                    True,
                    f"matched asn {normalized}",
                    self.manifest_id,
                    self.mode,
                )

        # Rule 5: deny
        return ScopeResult(
            False, "no scope rule matched", self.manifest_id, self.mode
        )


def load_manifest(path: Path) -> ScopeManifest:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return ScopeManifest.from_dict(raw)


# ---------------------------------------------------------------------------


def _parse_iso(s: str) -> datetime:
    s = str(s)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _normalize_asn(asn: str) -> str:
    s = str(asn).strip().upper()
    if not s.startswith("AS"):
        s = "AS" + s
    return s


def _resolve_target_for_match(target: Target) -> tuple[str, Optional[str]]:
    """Return (canonical_value, error). canonical_value is host (for URL),
    ip string (for ip), or raw value otherwise."""
    if target.kind == "url":
        try:
            host = urlparse(
                target.value if "://" in target.value else "https://" + target.value
            ).hostname
            if not host:
                return "", f"invalid url: {target.value}"
            return host.lower(), None
        except Exception as exc:
            return "", f"invalid url: {exc}"
    if target.kind == "ip":
        try:
            ipaddress.ip_address(target.value)
            return target.value, None
        except ValueError:
            return "", f"invalid ip: {target.value!r}"
    if target.kind == "cidr":
        try:
            ipaddress.ip_network(target.value, strict=False)
            return target.value, None
        except ValueError:
            return "", f"invalid cidr: {target.value!r}"
    if target.kind == "asn":
        return target.value, None
    return target.value, None


def _domain_match(host: str, pattern: str) -> bool:
    host = host.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".acme.com"
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return host == pattern
