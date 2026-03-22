from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scopeguard.scope.errors import ScopeValidationError
from scopeguard.scope.loader import load_scope_package


def test_demo_scope_loads() -> None:
    scope = load_scope_package(Path("examples/scope.demo.yaml"))
    assert scope.primary_domain == "demo.example"
    assert scope.base_host == "demo.example"
    assert "header-review" in scope.tool_allowlist


def test_rejects_wildcard_entries(tmp_path: Path) -> None:
    scope_path = tmp_path / "scope.yaml"
    payload = {
        "version": 1,
        "name": "Bad Scope",
        "primary_domain": "demo.example",
        "base_url": "https://demo.example",
        "allowed_subdomains": ["*.demo.example"],
        "allowed_urls": ["https://demo.example/"],
        "out_of_scope_assets": [],
        "login_areas_allowed": ["/login"],
        "apis_allowed": [],
        "tool_allowlist": ["header-review"],
        "authorization_note": "Authorized.",
    }
    scope_path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(ScopeValidationError):
        load_scope_package(scope_path)


def test_rejects_unlisted_allowed_url_host(tmp_path: Path) -> None:
    scope_path = tmp_path / "scope.yaml"
    payload = {
        "version": 1,
        "name": "Bad Scope",
        "primary_domain": "demo.example",
        "base_url": "https://demo.example",
        "allowed_subdomains": ["www.demo.example"],
        "allowed_urls": ["https://evil.example/"],
        "out_of_scope_assets": [],
        "login_areas_allowed": ["/login"],
        "apis_allowed": [],
        "tool_allowlist": ["header-review"],
        "authorization_note": "Authorized.",
    }
    scope_path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(ScopeValidationError):
        load_scope_package(scope_path)

