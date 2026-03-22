from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from httpx import RequestError

from .base import ExecutionContext


@dataclass(slots=True)
class HttpFetchResult:
    requested_url: str
    final_url: str
    status_code: int | None
    headers: dict[str, str]
    set_cookie_headers: list[str]
    body: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "headers": self.headers,
            "set_cookie_headers": self.set_cookie_headers,
            "body": self.body,
            "error": self.error,
        }


def safe_fetch(
    context: ExecutionContext,
    url: str,
    *,
    method: str = "GET",
) -> HttpFetchResult:
    if url in context.cache:
        return context.cache[url]

    try:
        response = context.http_client.request(
            method,
            url,
            headers={"User-Agent": context.user_agent},
        )
        body = response.text[: context.max_body_chars]
        result = HttpFetchResult(
            requested_url=url,
            final_url=str(response.url),
            status_code=response.status_code,
            headers={key.lower(): value for key, value in response.headers.items()},
            set_cookie_headers=list(response.headers.get_list("set-cookie")),
            body=body,
        )
    except RequestError as exc:
        result = HttpFetchResult(
            requested_url=url,
            final_url=url,
            status_code=None,
            headers={},
            set_cookie_headers=[],
            body="",
            error=str(exc),
        )

    context.cache[url] = result
    return result


def same_host_url(base_url: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    parsed = urlparse(base_url)
    return f"{parsed.scheme}://{parsed.netloc}{path}"
