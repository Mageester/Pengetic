from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address
import re
from urllib.parse import urlparse

from pydantic import AnyUrl, BaseModel, ConfigDict, Field, field_validator, model_validator

from .errors import ScopeValidationError


HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)


def _as_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    return [str(item).strip() for item in value if str(item).strip()]


def _normalize_host(host: str) -> str:
    normalized = host.strip().lower()
    if not normalized or "://" in normalized:
        raise ScopeValidationError(f"Invalid host entry: {host!r}")
    if "*" in normalized:
        raise ScopeValidationError(f"Wildcards are not allowed in host entries: {host!r}")
    try:
        ip_address(normalized)
        return normalized
    except ValueError:
        pass
    if normalized == "localhost":
        return normalized
    if not HOST_RE.fullmatch(normalized):
        raise ScopeValidationError(f"Invalid host entry: {host!r}")
    return normalized


def _normalize_route(route: str) -> str:
    normalized = route.strip()
    if not normalized:
        raise ScopeValidationError("Route entries must not be empty.")
    if "*" in normalized:
        raise ScopeValidationError(f"Wildcards are not allowed in route entries: {route!r}")
    if "://" in normalized:
        parsed = urlparse(normalized)
        if not parsed.hostname:
            raise ScopeValidationError(f"Invalid route URL: {route!r}")
        if parsed.fragment:
            normalized = normalized.split("#", 1)[0]
        return normalized
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def _host_from_value(value: str) -> str | None:
    if "://" not in value:
        return None
    host = urlparse(value).hostname
    return host.lower() if host else None


class RateLimitPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    max_requests_per_minute: int = Field(default=60, ge=1)
    max_concurrent_requests: int = Field(default=2, ge=1, le=32)
    delay_seconds_between_requests: float = Field(default=0.5, ge=0)


class TestingWindow(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    start: datetime | None = None
    end: datetime | None = None

    @model_validator(mode="after")
    def validate_bounds(self) -> "TestingWindow":
        if self.start and self.end and self.start > self.end:
            raise ScopeValidationError("testing_window.start must be before testing_window.end")
        return self


class ScopePackage(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    version: int = Field(default=1, ge=1)
    name: str
    primary_domain: str
    base_url: AnyUrl
    allowed_subdomains: list[str] = Field(default_factory=list)
    allowed_urls: list[AnyUrl] = Field(default_factory=list)
    out_of_scope_assets: list[str] = Field(default_factory=list)
    login_areas_allowed: list[str] = Field(default_factory=list)
    apis_allowed: list[str] = Field(default_factory=list)
    tool_allowlist: list[str] = Field(default_factory=list)
    rate_limits: RateLimitPolicy = Field(default_factory=RateLimitPolicy)
    testing_window: TestingWindow | None = None
    authorization_note: str
    contacts: list[str] = Field(default_factory=list)
    notes: str | None = None

    @field_validator(
        "allowed_subdomains",
        "out_of_scope_assets",
        "login_areas_allowed",
        "apis_allowed",
        "tool_allowlist",
        "contacts",
        mode="before",
    )
    @classmethod
    def normalize_lists(cls, value: object) -> list[str]:
        return _as_list(value)

    @field_validator("primary_domain")
    @classmethod
    def normalize_primary_domain(cls, value: str) -> str:
        return _normalize_host(value)

    @field_validator("allowed_subdomains")
    @classmethod
    def validate_allowed_subdomains(cls, value: list[str]) -> list[str]:
        return [_normalize_host(item) for item in value]

    @field_validator("login_areas_allowed", "apis_allowed")
    @classmethod
    def normalize_routes(cls, value: list[str]) -> list[str]:
        return [_normalize_route(item) for item in value]

    @field_validator("authorization_note")
    @classmethod
    def ensure_authorization_note(cls, value: str) -> str:
        if not value.strip():
            raise ScopeValidationError("authorization_note is required.")
        return value.strip()

    @model_validator(mode="after")
    def validate_scope_constraints(self) -> "ScopePackage":
        primary = self.primary_domain.lower()
        base_host = self.base_host
        authorized_hosts = {primary, base_host, *self.allowed_subdomains}

        if "*" in str(self.base_url):
            raise ScopeValidationError("Wildcards are not allowed in base_url.")

        for item in self.out_of_scope_assets + self.tool_allowlist:
            if "*" in item:
                raise ScopeValidationError(f"Wildcards are not allowed in scope entries: {item!r}")

        if base_host not in authorized_hosts:
            raise ScopeValidationError(
                f"base_url host '{base_host}' must match primary_domain or an allowed subdomain."
            )

        for url in self.allowed_urls:
            if url.host is None:
                raise ScopeValidationError(f"Invalid allowed URL: {url!s}")
            host = url.host.lower()
            if "*" in str(url):
                raise ScopeValidationError(f"Wildcards are not allowed in allowed_urls: {url!s}")
            if host not in authorized_hosts:
                raise ScopeValidationError(
                    f"allowed_urls host '{host}' is not covered by primary_domain/allowed_subdomains."
                )

        for route in self.login_areas_allowed + self.apis_allowed:
            host = _host_from_value(route)
            if host and host not in authorized_hosts:
                raise ScopeValidationError(
                    f"Route host '{host}' is not covered by primary_domain/allowed_subdomains."
                )

        if not self.tool_allowlist:
            raise ScopeValidationError("tool_allowlist must contain at least one approved tool.")

        return self

    @property
    def base_host(self) -> str:
        host = self.base_url.host
        if host is None:
            raise ScopeValidationError("base_url must include a host.")
        return host.lower()

    @property
    def authorized_hosts(self) -> list[str]:
        hosts = {self.primary_domain.lower(), self.base_host, *self.allowed_subdomains}
        for url in self.allowed_urls:
            if url.host:
                hosts.add(url.host.lower())
        for route in self.login_areas_allowed + self.apis_allowed:
            host = _host_from_value(route)
            if host:
                hosts.add(host)
        return sorted(hosts)

    def canonical_dict(self) -> dict[str, object]:
        return self.model_dump(mode="json")
