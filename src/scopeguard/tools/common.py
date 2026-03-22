from __future__ import annotations

from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

from .base import ExecutionContext


def scope_base_url(context: ExecutionContext) -> str:
    return str(context.scope.base_url)


def make_evidence_name(context: ExecutionContext, tool_id: str, suffix: str) -> str:
    safe_tool = tool_id.replace("/", "-")
    return f"{context.run_id}/{safe_tool}-{suffix}"


class LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[str] = []
        self.meta: dict[str, list[str]] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key.lower(): value for key, value in attrs if value is not None}
        if tag in {"a", "link", "script", "img"}:
            target = attr_map.get("href") or attr_map.get("src")
            if target:
                self.links.append(target)
        if tag == "form":
            action = attr_map.get("action")
            if action:
                self.forms.append(action)
        if tag == "meta":
            key = (attr_map.get("name") or attr_map.get("property") or "").lower()
            content = attr_map.get("content")
            if key and content:
                self.meta.setdefault(key, []).append(content)


def parse_same_host_paths(html: str, base_url: str, allowed_hosts: set[str]) -> set[str]:
    parser = LinkExtractor()
    parser.feed(html)
    discovered: set[str] = set()
    for raw_link in [*parser.links, *parser.forms]:
        absolute = urljoin(base_url, raw_link)
        parsed = urlparse(absolute)
        if not parsed.hostname:
            continue
        host = parsed.hostname.lower()
        if host not in allowed_hosts:
            continue
        discovered.add(parsed.path or "/")
    return discovered

