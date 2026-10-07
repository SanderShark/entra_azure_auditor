"""Thin Microsoft Graph client: paging, throttling-aware retry, OData helpers.

Deliberately small. Collectors call ``get_paged("/users", select=[...])`` and
get plain dicts back; parsing into models happens elsewhere.

Testing hooks: pass ``transport=`` (e.g. ``httpx.MockTransport`` or a respx
router) and ``sleep=`` (a no-op) to make retry tests instant and offline.
"""

from __future__ import annotations

import logging
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Mapping, Sequence
from urllib.parse import urlsplit

import httpx

from ..auth import TokenProvider

log = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://graph.microsoft.com/v1.0"
# Throttling (429) and transient server-side failures.
RETRY_STATUSES = frozenset({429, 502, 503, 504})


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class GraphError(Exception):
    """Any failed Graph call. Carries Graph's error code and request id."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        request_id: str | None = None,
        url: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.request_id = request_id
        self.url = url


class GraphAuthError(GraphError):
    """401: token missing, expired, or for the wrong resource."""


class GraphPermissionError(GraphError):
    """403: the app/user lacks the permission (or license) for this endpoint."""


class GraphNotFoundError(GraphError):
    """404: resource doesn't exist."""


class GraphRetryExhaustedError(GraphError):
    """Still throttled / failing after all retries."""


@dataclass(frozen=True)
class GraphResponse:
    """Result of a write call: status, headers (lower-cased names) and the JSON body, if any."""
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] = field(default_factory=dict)

    @property
    def location(self) -> str | None:
        """Operation URL for long-running calls (e.g. password reset returns 202 + Location)."""
        return self.headers.get("location")


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

class GraphClient:
    def __init__(
        self,
        token_provider: TokenProvider,
        *,
        base_url: str = DEFAULT_BASE_URL,
        max_retries: int = 5,
        backoff_base: float = 1.0,
        max_delay: float = 60.0,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._tokens = token_provider
        self._base_url = base_url.rstrip("/")
        self._host = urlsplit(self._base_url).netloc
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._max_delay = max_delay
        self._sleep = sleep
        self._http = httpx.Client(timeout=timeout, transport=transport)

    # -- lifecycle ---------------------------------------------------------- #

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "GraphClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- public API --------------------------------------------------------- #

    def get(
        self,
        path: str,
        *,
        select: Sequence[str] | None = None,
        filter: str | None = None,
        expand: str | None = None,
        params: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """GET a single resource (or any non-paged response) as a dict."""
        query = self._odata_params(select=select, filter=filter, expand=expand, extra=params)
        response = self._request("GET", self._url(path), params=query)
        return response.json() if response.content else {}

    def get_paged(
        self,
        path: str,
        *,
        select: Sequence[str] | None = None,
        filter: str | None = None,
        expand: str | None = None,
        top: int | None = None,
        count: bool = False,
        params: Mapping[str, str] | None = None,
        max_pages: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Yield every item of a collection, following ``@odata.nextLink``.

        ``select`` trims the payload to the properties you need (faster, and
        avoids pulling data you don't want stored). ``count=True`` enables
        advanced queries, which Graph requires ``ConsistencyLevel: eventual``
        for; the header is added automatically.
        """
        query: dict[str, str] | None = self._odata_params(
            select=select, filter=filter, expand=expand, top=top, count=count, extra=params
        )
        headers = {"ConsistencyLevel": "eventual"} if count else None
        url: str | None = self._url(path)
        pages = 0

        while url:
            response = self._request("GET", url, params=query, headers=headers)
            body = response.json()
            if "value" not in body:
                raise GraphError(
                    f"Expected a collection ('value') from {url}", url=url,
                    status_code=response.status_code,
                )
            yield from body["value"]

            pages += 1
            if max_pages is not None and pages >= max_pages:
                return

            url = body.get("@odata.nextLink")
            if url:
                self._check_same_host(url)
            query = None  # nextLink already embeds every query option

    def get_all(self, path: str, **kwargs: Any) -> list[dict[str, Any]]:
        """Like ``get_paged`` but returns a list."""
        return list(self.get_paged(path, **kwargs))

    # -- writes ------------------------------------------------------------- #
    # Retry rules differ from reads: a 429 is always safe to resend (it was rejected before
    # being processed), but after a 5xx or network error a POST may already have been applied,
    # so POSTs are never re-sent in that case. PATCH/DELETE/PUT are idempotent and are.

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Mapping[str, Any] | None = None,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        idempotent: bool | None = None,
    ) -> GraphResponse:
        method = method.upper()
        if idempotent is None:
            idempotent = method != "POST"
        response = self._request(
            method, self._url(path), params=params, headers=headers, json=json, idempotent=idempotent
        )
        body: dict[str, Any] = {}
        if response.content:
            try:
                parsed = response.json()
                body = parsed if isinstance(parsed, dict) else {"value": parsed}
            except ValueError:
                body = {}
        return GraphResponse(
            status_code=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            body=body,
        )

    def post(self, path: str, json: Mapping[str, Any] | None = None, **kwargs: Any) -> GraphResponse:
        return self.request("POST", path, json=json, **kwargs)

    def patch(self, path: str, json: Mapping[str, Any], **kwargs: Any) -> GraphResponse:
        return self.request("PATCH", path, json=json, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> GraphResponse:
        return self.request("DELETE", path, **kwargs)

    # -- internals ---------------------------------------------------------- #

    def _url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self._base_url}/{path.lstrip('/')}"

    def _check_same_host(self, url: str) -> None:
        # We attach a bearer token to nextLink requests, so never follow a link
        # to another host: that would leak the token.
        if urlsplit(url).netloc != self._host:
            raise GraphError(f"Refusing to follow nextLink to unexpected host: {url}")

    @staticmethod
    def _odata_params(
        *,
        select: Sequence[str] | None = None,
        filter: str | None = None,
        expand: str | None = None,
        top: int | None = None,
        count: bool = False,
        extra: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        query: dict[str, str] = dict(extra or {})
        if select:
            query["$select"] = ",".join(select)
        if filter:
            query["$filter"] = filter
        if expand:
            query["$expand"] = expand
        if top:
            query["$top"] = str(top)
        if count:
            query["$count"] = "true"
        return query

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        json: Mapping[str, Any] | None = None,
        idempotent: bool = True,
    ) -> httpx.Response:
        request_id = str(uuid.uuid4())  # same id across retries, for Microsoft support
        attempt = 0
        # 429 means "rejected before processing": always safe to resend. 5xx and network
        # errors are ambiguous for a write, so non-idempotent calls only retry on 429.
        retry_statuses = RETRY_STATUSES if idempotent else frozenset({429})

        while True:
            # Fetch the token per attempt: the provider caches, and a long
            # audit may outlive a single token's lifetime.
            call_headers = {
                "Authorization": f"Bearer {self._tokens.get_token()}",
                "Accept": "application/json",
                "client-request-id": request_id,
                **(headers or {}),
            }

            try:
                response = self._http.request(
                    method, url, params=params, headers=call_headers, json=json
                )
            except httpx.TransportError as exc:  # timeouts, connection resets, DNS
                if not idempotent:
                    raise GraphError(
                        f"Network error; the request may or may not have been applied: {exc}",
                        url=url,
                    ) from exc
                if attempt >= self._max_retries:
                    raise GraphRetryExhaustedError(
                        f"Network error after {attempt} retries: {exc}", url=url
                    ) from exc
                self._wait(attempt, None, reason=type(exc).__name__)
                attempt += 1
                continue

            if response.status_code in retry_statuses:
                if attempt >= self._max_retries:
                    raise self._error_from(response, url, exhausted=True)
                self._wait(attempt, response.headers.get("Retry-After"),
                           reason=str(response.status_code))
                attempt += 1
                continue

            if response.is_success:
                return response
            raise self._error_from(response, url)

    def _wait(self, attempt: int, retry_after: str | None, *, reason: str) -> None:
        delay = self._retry_delay(attempt, retry_after)
        log.warning("Graph call retry %d in %.1fs (%s)", attempt + 1, delay, reason)
        self._sleep(delay)

    def _retry_delay(self, attempt: int, retry_after: str | None) -> float:
        """Honor Retry-After when present, else exponential backoff with jitter."""
        if retry_after:
            try:
                return min(max(float(retry_after), 0.0), self._max_delay)
            except ValueError:
                pass  # HTTP-date form is rare for Graph; fall back to backoff
        backoff = self._backoff_base * (2 ** attempt)
        return min(backoff + random.uniform(0, backoff / 2), self._max_delay)

    @staticmethod
    def _error_from(response: httpx.Response, url: str, *, exhausted: bool = False) -> GraphError:
        code = message = None
        try:
            err = response.json().get("error", {})
            code, message = err.get("code"), err.get("message")
        except (ValueError, AttributeError):
            pass
        message = message or response.text[:200] or response.reason_phrase

        status = response.status_code
        kwargs = dict(
            status_code=status,
            code=code,
            request_id=response.headers.get("request-id"),
            url=url,
        )
        text = f"Graph {status} {code or ''}: {message}".replace("  ", " ")

        if exhausted:
            return GraphRetryExhaustedError(f"{text} (retries exhausted)", **kwargs)
        if status == 401:
            return GraphAuthError(text, **kwargs)
        if status == 403:
            return GraphPermissionError(text, **kwargs)
        if status == 404:
            return GraphNotFoundError(text, **kwargs)
        return GraphError(text, **kwargs)
