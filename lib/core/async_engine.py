#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GenSQL - Advanced SQL Injection & Web Security Assessment Framework
lib/core/async_engine.py

Asyncio-based concurrent scan engine for high-performance, adaptive
HTTP request dispatch during SQL injection assessments.

Author  : Jeevraj
Project : GenSQL (Enhanced sqlmap fork)
License : GNU GPLv2

Architecture
------------
AsyncScanEngine
  ├─ AsyncHTTPClient  (httpx → urllib fallback, keep-alive connection pool)
  ├─ asyncio.Semaphore (concurrency gate)
  ├─ asyncio.Queue     (payload work queue)
  ├─ MetricsCollector  (req/s, latency p95, success rate)
  └─ AdaptiveTuner     (adjusts semaphore at runtime)
"""

import asyncio
import math
import random
import logging
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional

# ── Optional third-party imports ────────────────────────────────────────────
try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

try:
    import h2  # noqa: F401
    _HTTP2_AVAILABLE = True
except ImportError:
    _HTTP2_AVAILABLE = False

try:
    import h3  # noqa: F401
    _HTTP3_AVAILABLE = True
except ImportError:
    _HTTP3_AVAILABLE = False

# ── sqlmap compat shims ──────────────────────────────────────────────────────
try:
    from lib.core.data import logger
    from lib.core.enums import HTTPMETHOD
    from lib.core.exception import (
        SqlmapConnectionException,
        SqlmapTimeoutException,
    )
except ImportError:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    logger = logging.getLogger("jeevsql.async_engine")

    class HTTPMETHOD:   # type: ignore[misc]
        GET  = "GET"
        POST = "POST"
        PUT  = "PUT"

    class SqlmapConnectionException(Exception): pass   # noqa: E701
    class SqlmapTimeoutException(Exception): pass       # noqa: E701

# ── Constants ────────────────────────────────────────────────────────────────
DEFAULT_MAX_CONCURRENT: int   = 50
DEFAULT_TIMEOUT:        int   = 30
DEFAULT_RETRIES:        int   = 3
BACKOFF_BASE:           float = 1.5
MAX_BACKOFF:            float = 60.0
JITTER_FRACTION:        float = 0.30
METRICS_WINDOW:         int   = 200
ADAPTIVE_CHECK_EVERY:   int   = 50
RATE_LIMIT_PAUSE:       float = 5.0


# ── Enumerations ─────────────────────────────────────────────────────────────

class HTTPVersion(Enum):
    """Supported HTTP protocol versions."""
    AUTO   = auto()
    HTTP11 = auto()
    HTTP2  = auto()
    HTTP3  = auto()


class ScanTechnique(Enum):
    """SQL injection technique identifiers (mirror sqlmap single-char flags)."""
    BOOLEAN_BLIND = "B"
    ERROR_BASED   = "E"
    UNION_BASED   = "U"
    STACKED_QUERY = "S"
    TIME_BLIND    = "T"
    INLINE_QUERY  = "Q"


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class HTTPResponse:
    """
    Normalised HTTP response container.

    Attributes
    ----------
    status_code  : HTTP status code.
    headers      : Response headers (lower-cased keys).
    body         : Decoded response body.
    latency      : Round-trip time in seconds.
    url          : Final (possibly redirected) URL.
    http_version : Protocol string e.g. "HTTP/2".
    error        : Non-None string description on failure.
    """
    status_code:  int
    headers:      Dict[str, str]
    body:         str
    latency:      float
    url:          str
    http_version: str           = "HTTP/1.1"
    error:        Optional[str] = None

    @property
    def ok(self) -> bool:
        """True when status_code is 2xx."""
        return 200 <= self.status_code < 300

    @property
    def is_rate_limited(self) -> bool:
        """True when status_code is 429."""
        return self.status_code == 429

    @property
    def is_server_error(self) -> bool:
        """True for 5xx responses."""
        return self.status_code >= 500


@dataclass
class ScanResult:
    """
    Aggregated result of a scan_target call.

    Attributes
    ----------
    url                : Target URL.
    technique          : Injection technique code.
    vulnerable         : True when at least one payload produced a signal.
    confirmed_payloads : Payloads that produced a positive signal.
    raw_responses      : Every HTTP response gathered.
    metrics            : Performance snapshot at scan completion.
    """
    url:                str
    technique:          str
    vulnerable:         bool               = False
    confirmed_payloads: List[str]          = field(default_factory=list)
    raw_responses:      List[HTTPResponse] = field(default_factory=list)
    metrics:            Dict[str, Any]     = field(default_factory=dict)


@dataclass
class RequestTask:
    """
    Single unit of work placed on the payload queue.

    Attributes
    ----------
    url     : Target URL.
    method  : HTTP verb.
    params  : Query-string parameters.
    data    : POST body parameters.
    headers : Request headers.
    cookies : Request cookies.
    payload : The SQL injection payload being tested.
    attempt : Retry counter.
    """
    url:     str
    method:  str
    params:  Dict[str, str]
    data:    Dict[str, str]
    headers: Dict[str, str]
    cookies: Dict[str, str]
    payload: str
    attempt: int = 0


# ── Metrics Collector ────────────────────────────────────────────────────────

class MetricsCollector:
    """
    Async-safe rolling-window metrics collector.

    Tracks per-request latency samples, success/failure counts,
    throughput (req/s), and rate-limit event count.

    Parameters
    ----------
    window : int
        FIFO buffer size for latency samples (default 200).
    """

    def __init__(self, window: int = METRICS_WINDOW) -> None:
        self._latencies:       deque = deque(maxlen=window)
        self._total_requests:  int   = 0
        self._total_successes: int   = 0
        self._total_failures:  int   = 0
        self._rate_limit_hits: int   = 0
        self._start_time:      float = time.monotonic()
        self._lock                   = asyncio.Lock()

    async def record(self, response: HTTPResponse) -> None:
        """Record a completed HTTPResponse into the rolling window."""
        async with self._lock:
            self._latencies.append(response.latency)
            self._total_requests += 1
            if response.error or response.is_server_error:
                self._total_failures += 1
            else:
                self._total_successes += 1
            if response.is_rate_limited:
                self._rate_limit_hits += 1

    async def snapshot(self) -> Dict[str, Any]:
        """
        Return a dict snapshot of current performance metrics.

        Keys: requests_per_sec, avg_latency_ms, p95_latency_ms,
              success_rate, total_requests, total_successes,
              total_failures, rate_limit_hits.
        """
        async with self._lock:
            elapsed = max(time.monotonic() - self._start_time, 0.001)
            lats    = list(self._latencies)
            avg_lat = statistics.mean(lats) * 1000 if lats else 0.0
            p95_lat = 0.0
            if lats:
                s       = sorted(lats)
                idx     = int(math.ceil(0.95 * len(s))) - 1
                p95_lat = s[max(idx, 0)] * 1000
            sr = (
                self._total_successes / self._total_requests
                if self._total_requests else 0.0
            )
            return {
                "requests_per_sec": round(self._total_requests / elapsed, 2),
                "avg_latency_ms":   round(avg_lat, 2),
                "p95_latency_ms":   round(p95_lat, 2),
                "success_rate":     round(sr,      4),
                "total_requests":   self._total_requests,
                "total_successes":  self._total_successes,
                "total_failures":   self._total_failures,
                "rate_limit_hits":  self._rate_limit_hits,
            }

    @property
    def avg_latency(self) -> float:
        """Current rolling-average latency in seconds (0 when no data)."""
        lats = list(self._latencies)
        return statistics.mean(lats) if lats else 0.0

    @property
    def total_requests(self) -> int:
        """Total requests recorded so far."""
        return self._total_requests


# ── Adaptive Concurrency Tuner ────────────────────────────────────────────────

class AdaptiveTuner:
    """
    Dynamically adjusts the semaphore concurrency ceiling.

    Rules
    -----
    - avg_latency < target_latency          → +10 % concurrency
    - avg_latency > target_latency * 2      → -20 % concurrency
    - HTTP 429 event                        → -50 % concurrency (immediate)
    - Hard bounds enforced: [min_limit, max_limit]

    Parameters
    ----------
    initial_limit  : Starting concurrency.
    min_limit      : Floor value (default 2).
    max_limit      : Ceiling value (default 200).
    target_latency : Desired avg response time in seconds (default 0.5).
    """

    def __init__(
        self,
        initial_limit:  int   = DEFAULT_MAX_CONCURRENT,
        min_limit:      int   = 2,
        max_limit:      int   = 200,
        target_latency: float = 0.5,
    ) -> None:
        self.current_limit  = initial_limit
        self.min_limit      = min_limit
        self.max_limit      = max_limit
        self.target_latency = target_latency
        self._lock          = asyncio.Lock()

    async def evaluate(
        self,
        metrics:      MetricsCollector,
        rate_limited: bool = False,
    ) -> int:
        """
        Evaluate metrics and return the new recommended concurrency limit.

        Parameters
        ----------
        metrics      : Live MetricsCollector instance.
        rate_limited : True when the triggering response was HTTP 429.

        Returns
        -------
        int
            New concurrency limit.
        """
        async with self._lock:
            if rate_limited:
                self.current_limit = max(
                    self.min_limit, int(self.current_limit * 0.50)
                )
                logger.debug(
                    "[AdaptiveTuner] 429 → concurrency=%d", self.current_limit
                )
                return self.current_limit

            avg = metrics.avg_latency
            if avg == 0.0:
                return self.current_limit

            if avg < self.target_latency:
                new = int(self.current_limit * 1.10)
            elif avg > self.target_latency * 2:
                new = int(self.current_limit * 0.80)
            else:
                return self.current_limit

            self.current_limit = max(self.min_limit, min(self.max_limit, new))
            logger.debug(
                "[AdaptiveTuner] avg=%.3fs → concurrency=%d",
                avg, self.current_limit,
            )
            return self.current_limit


# ── Async HTTP Client ─────────────────────────────────────────────────────────

class AsyncHTTPClient:
    """
    Thin async HTTP wrapper with graceful degradation.

    Priority:
      1. httpx + HTTP/2 (when h2 is installed)
      2. httpx + HTTP/1.1
      3. stdlib urllib (blocking, offloaded to thread executor)

    Parameters
    ----------
    timeout         : Per-request timeout in seconds.
    http_version    : Desired HTTPVersion enum value.
    max_connections : Connection pool size.
    """

    def __init__(
        self,
        timeout:         float       = DEFAULT_TIMEOUT,
        http_version:    HTTPVersion = HTTPVersion.AUTO,
        max_connections: int         = DEFAULT_MAX_CONCURRENT,
    ) -> None:
        self.timeout         = timeout
        self.http_version    = http_version
        self.max_connections = max_connections
        self._client: Optional[Any] = None
        self._use_httpx      = _HTTPX_AVAILABLE
        self._http2_enabled  = False

    async def init(self) -> None:
        """
        Initialise the connection pool.
        Must be awaited before dispatching any requests.
        """
        if not self._use_httpx:
            logger.warning(
                "[AsyncHTTPClient] httpx unavailable – using urllib fallback"
            )
            return

        use_http2 = (
            _HTTP2_AVAILABLE
            and self.http_version in (HTTPVersion.AUTO, HTTPVersion.HTTP2)
        )
        limits = httpx.Limits(
            max_connections=self.max_connections,
            max_keepalive_connections=self.max_connections,
            keepalive_expiry=20,
        )
        self._client = httpx.AsyncClient(
            http2=use_http2,
            timeout=httpx.Timeout(self.timeout),
            limits=limits,
            follow_redirects=True,
            verify=False,
        )
        self._http2_enabled = use_http2
        logger.debug(
            "[AsyncHTTPClient] ready – http2=%s", use_http2
        )

    async def close(self) -> None:
        """Close the connection pool gracefully."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def request(
        self,
        method:  str,
        url:     str,
        params:  Optional[Dict[str, str]] = None,
        data:    Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> HTTPResponse:
        """
        Dispatch one HTTP request and return a normalised HTTPResponse.

        Parameters
        ----------
        method  : HTTP verb in upper-case.
        url     : Absolute target URL.
        params  : URL query parameters.
        data    : POST form body.
        headers : Extra request headers.
        cookies : Cookie mapping.

        Returns
        -------
        HTTPResponse
            error field is set (non-None) on network / timeout failure.
        """
        if self._use_httpx and self._client is not None:
            return await self._httpx_req(method, url, params, data, headers, cookies)
        return await self._urllib_req(method, url, params, data, headers, cookies)

    async def _httpx_req(
        self,
        method:  str,
        url:     str,
        params:  Optional[Dict[str, str]],
        data:    Optional[Dict[str, str]],
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]],
    ) -> HTTPResponse:
        t0 = time.monotonic()
        try:
            r = await self._client.request(
                method=method, url=url,
                params=params   or {},
                data=data       or {},
                headers=headers or {},
                cookies=cookies or {},
            )
            lat   = time.monotonic() - t0
            proto = "HTTP/2" if self._http2_enabled else "HTTP/1.1"
            return HTTPResponse(
                status_code=r.status_code,
                headers=dict(r.headers),
                body=r.text,
                latency=lat,
                url=str(r.url),
                http_version=proto,
            )
        except httpx.TimeoutException as exc:
            lat = time.monotonic() - t0
            return HTTPResponse(0, {}, "", lat, url, error=f"Timeout: {exc}")
        except httpx.RequestError as exc:
            lat = time.monotonic() - t0
            return HTTPResponse(0, {}, "", lat, url, error=f"RequestError: {exc}")
        except Exception as exc:
            lat = time.monotonic() - t0
            return HTTPResponse(0, {}, "", lat, url, error=f"Unexpected: {exc}")

    async def _urllib_req(
        self,
        method:  str,
        url:     str,
        params:  Optional[Dict[str, str]],
        data:    Optional[Dict[str, str]],
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]],
    ) -> HTTPResponse:
        loop = asyncio.get_event_loop()
        t0   = time.monotonic()

        def _sync() -> HTTPResponse:
            try:
                full_url = url
                if params:
                    full_url = f"{url}?{urllib.parse.urlencode(params)}"
                body_bytes: Optional[bytes] = (
                    urllib.parse.urlencode(data).encode() if data else None
                )
                req = urllib.request.Request(
                    full_url, data=body_bytes,
                    headers=headers or {}, method=method,
                )
                if cookies:
                    req.add_header(
                        "Cookie",
                        "; ".join(f"{k}={v}" for k, v in cookies.items()),
                    )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    lat  = time.monotonic() - t0
                    body = resp.read().decode("utf-8", errors="replace")
                    hdrs = {k.lower(): v for k, v in resp.getheaders()}
                    return HTTPResponse(resp.status, hdrs, body, lat, resp.url)
            except urllib.error.HTTPError as exc:
                lat = time.monotonic() - t0
                return HTTPResponse(
                    exc.code, {}, exc.read().decode("utf-8", errors="replace"),
                    lat, url, error=f"HTTPError {exc.code}: {exc.reason}",
                )
            except Exception as exc:
                lat = time.monotonic() - t0
                return HTTPResponse(0, {}, "", lat, url, error=str(exc))

        return await loop.run_in_executor(None, _sync)


# ── Retry helper ──────────────────────────────────────────────────────────────

def compute_backoff(attempt: int, base: float = BACKOFF_BASE) -> float:
    """
    Exponential back-off with multiplicative jitter.

    Formula: delay = min(base^attempt, MAX_BACKOFF) * U(1-J, 1+J)

    Parameters
    ----------
    attempt : int   – zero-based retry attempt index.
    base    : float – exponential base (default 1.5).

    Returns
    -------
    float – seconds to sleep before next attempt.
    """
    raw    = min(base ** attempt, MAX_BACKOFF)
    jitter = random.uniform(1.0 - JITTER_FRACTION, 1.0 + JITTER_FRACTION)
    return raw * jitter


# ── Async Scan Engine ─────────────────────────────────────────────────────────

class AsyncScanEngine:
    """
    High-performance asyncio-based SQL injection scan orchestrator.

    Key capabilities
    ----------------
    * Semaphore-gated concurrency (starts at max_concurrent, tuned at runtime).
    * asyncio.Queue-based work distribution – payloads are processed as soon
      as a worker slot becomes free.
    * Adaptive concurrency control via AdaptiveTuner.
    * HTTP 429 handling: Retry-After header honoured, exponential fall-back.
    * Smart retry with exponential back-off + jitter (up to DEFAULT_RETRIES).
    * Rich metrics: req/s, avg/p95 latency, success rate, rate-limit hits.
    * HTTP/1.1, HTTP/2 (with h2), and urllib fall-back.

    Parameters
    ----------
    max_concurrent : int – starting concurrency limit (default 50).
    http_version   : str – "auto" | "http1" | "http2" | "http3".
    timeout        : int – per-request timeout in seconds (default 30).

    Example
    -------
    >>> engine = AsyncScanEngine(max_concurrent=30, timeout=15)
    >>> await engine.init()
    >>> result = await engine.scan_target(
    ...     url="https://target.example.com/search",
    ...     payloads=["' OR 1=1--", "' AND SLEEP(5)--"],
    ...     parameters={"q": "test"},
    ...     technique="B",
    ... )
    >>> await engine.close()
    """

    _VERSION_MAP: Dict[str, HTTPVersion] = {
        "auto":  HTTPVersion.AUTO,
        "http1": HTTPVersion.HTTP11,
        "http2": HTTPVersion.HTTP2,
        "http3": HTTPVersion.HTTP3,
    }

    def __init__(
        self,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        http_version:   str = "auto",
        timeout:        int = DEFAULT_TIMEOUT,
    ) -> None:
        self.max_concurrent  = max_concurrent
        self.timeout         = timeout
        self.http_version    = self._VERSION_MAP.get(
            http_version.lower(), HTTPVersion.AUTO
        )
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._client:    Optional[AsyncHTTPClient]   = None
        self._metrics    = MetricsCollector()
        self._tuner      = AdaptiveTuner(initial_limit=max_concurrent)
        self._req_count: int   = 0
        self._rl_ts:     float = 0.0   # last 429 timestamp
        self._ready:     bool  = False

    # ── lifecycle ─────────────────────────────────────────────────────────────

    async def init(self) -> None:
        """
        Initialise the engine.
        Must be awaited before calling scan_target or send_request.
        """
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._client    = AsyncHTTPClient(
            timeout=self.timeout,
            http_version=self.http_version,
            max_connections=self.max_concurrent,
        )
        await self._client.init()
        self._ready = True
        logger.info(
            "[AsyncScanEngine] ready – max_concurrent=%d http_version=%s",
            self.max_concurrent, self.http_version.name,
        )

    async def close(self) -> None:
        """Release all resources. Call when scanning is complete."""
        if self._client:
            await self._client.close()
        self._ready = False
        logger.debug("[AsyncScanEngine] closed.")

    # ── public API ────────────────────────────────────────────────────────────

    async def scan_target(
        self,
        url:        str,
        payloads:   List[str],
        parameters: Dict[str, str],
        technique:  str,
    ) -> ScanResult:
        """
        Concurrently scan *url* with all *payloads*.

        For each (parameter_key, payload) pair a RequestTask is enqueued.
        Worker coroutines consume tasks, call _execute_with_retry, and
        aggregate results into a ScanResult.

        Parameters
        ----------
        url        : Absolute target URL.
        payloads   : SQL injection payloads.
        parameters : Baseline parameters; each key is tested individually.
        technique  : Single-char technique code (B/E/U/S/T/Q).

        Returns
        -------
        ScanResult
        """
        if not self._ready:
            await self.init()

        result: ScanResult = ScanResult(url=url, technique=technique)
        queue: asyncio.Queue = asyncio.Queue()

        for key in parameters:
            for payload in payloads:
                injected = {**parameters, key: payload}
                await queue.put(RequestTask(
                    url=url, method=HTTPMETHOD.GET,
                    params=injected, data={},
                    headers=self._default_headers(),
                    cookies={}, payload=payload,
                ))

        total       = queue.qsize()
        num_workers = min(self.max_concurrent, max(total, 1))
        responses:  List[HTTPResponse] = []
        lock        = asyncio.Lock()

        logger.info(
            "[AsyncScanEngine] scan_target url=%s tasks=%d workers=%d",
            url, total, num_workers,
        )

        async def _worker() -> None:
            while True:
                task = await queue.get()
                if task is None:
                    queue.task_done()
                    break
                resp = await self._execute_with_retry(task)
                await self._metrics.record(resp)
                async with lock:
                    responses.append(resp)
                    if self._positive_signal(resp, technique):
                        result.vulnerable = True
                        result.confirmed_payloads.append(task.payload)
                self._req_count += 1
                if self._req_count % ADAPTIVE_CHECK_EVERY == 0:
                    await self.adaptive_concurrency_control()
                queue.task_done()

        tasks = [asyncio.create_task(_worker()) for _ in range(num_workers)]
        await queue.join()
        for _ in range(num_workers):
            await queue.put(None)
        await asyncio.gather(*tasks, return_exceptions=True)

        result.raw_responses = responses
        result.metrics       = await self._metrics.snapshot()
        logger.info(
            "[AsyncScanEngine] done – vulnerable=%s confirmed=%d metrics=%s",
            result.vulnerable, len(result.confirmed_payloads), result.metrics,
        )
        return result

    async def send_request(
        self,
        url:     str,
        method:  str                      = HTTPMETHOD.GET,
        params:  Optional[Dict[str, str]] = None,
        data:    Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> HTTPResponse:
        """
        Dispatch a single semaphore-gated HTTP request (public API).

        Handles rate-limit responses automatically and records metrics.

        Parameters
        ----------
        url     : Absolute URL.
        method  : HTTP verb (default GET).
        params  : Query-string parameters.
        data    : POST form body.
        headers : Additional headers.
        cookies : Cookie mapping.

        Returns
        -------
        HTTPResponse
        """
        if not self._ready:
            await self.init()
        assert self._semaphore and self._client

        async with self._semaphore:
            resp = await self._client.request(
                method=method, url=url,
                params=params, data=data,
                headers=headers, cookies=cookies,
            )
        await self._metrics.record(resp)
        if resp.is_rate_limited:
            await self.rate_limit_handler(resp)
        return resp

    async def adaptive_concurrency_control(self) -> None:
        """
        Query AdaptiveTuner and update the semaphore limit if needed.

        Called automatically every ADAPTIVE_CHECK_EVERY requests during
        scan_target, and may be called manually at any time.
        """
        assert self._semaphore is not None
        rl         = (time.monotonic() - self._rl_ts) < 2.0
        new_limit  = await self._tuner.evaluate(self._metrics, rl)
        if new_limit != self.max_concurrent:
            self._semaphore     = asyncio.Semaphore(new_limit)
            self.max_concurrent = new_limit
            logger.debug("[AsyncScanEngine] semaphore → %d", new_limit)

    async def rate_limit_handler(self, response: HTTPResponse) -> None:
        """
        Handle an HTTP 429 response.

        Honurs Retry-After when present.  Falls back to exponentially
        growing pauses based on rate_limit_hits count.

        Parameters
        ----------
        response : The 429 HTTPResponse.
        """
        self._rl_ts = time.monotonic()
        ra = response.headers.get("retry-after", "")
        try:
            wait = float(ra)
        except (ValueError, TypeError):
            hits = self._metrics._rate_limit_hits
            wait = min(RATE_LIMIT_PAUSE * (2 ** max(hits - 1, 0)), MAX_BACKOFF)

        logger.warning("[AsyncScanEngine] HTTP 429 – pausing %.1fs", wait)
        await asyncio.sleep(wait)
        await self.adaptive_concurrency_control()

    async def get_metrics(self) -> Dict[str, Any]:
        """Return a live performance metrics snapshot."""
        return await self._metrics.snapshot()

    # ── internals ────────────────────────────────────────────────────────────

    async def _execute_with_retry(self, task: RequestTask) -> HTTPResponse:
        """
        Execute a RequestTask with exponential back-off retry logic.

        Retries up to DEFAULT_RETRIES times on network errors.
        Rate-limit responses trigger rate_limit_handler before retrying.

        Parameters
        ----------
        task : RequestTask to execute.

        Returns
        -------
        HTTPResponse – last received response.
        """
        assert self._semaphore and self._client
        resp: Optional[HTTPResponse] = None

        for attempt in range(DEFAULT_RETRIES + 1):
            task.attempt = attempt
            async with self._semaphore:
                resp = await self._client.request(
                    method=task.method, url=task.url,
                    params=task.params,
                    data=task.data or None,
                    headers=task.headers,
                    cookies=task.cookies or None,
                )

            if resp.is_rate_limited:
                await self.rate_limit_handler(resp)
                continue

            if resp.error and attempt < DEFAULT_RETRIES:
                delay = compute_backoff(attempt)
                logger.debug(
                    "[AsyncScanEngine] retry %d/%d in %.2fs err=%s",
                    attempt + 1, DEFAULT_RETRIES, delay, resp.error,
                )
                await asyncio.sleep(delay)
                continue

            return resp

        return resp   # type: ignore[return-value]

    @staticmethod
    def _positive_signal(response: HTTPResponse, technique: str) -> bool:
        """
        Heuristic detection of a successful SQL injection signal.

        Technique-specific logic:
        - E (error-based) : DB error strings in body.
        - T (time-blind)  : latency > 4 s.
        - U (union)       : GenSQL marker strings in body.
        - B (boolean)     : 200 response with non-empty body (caller
                            must compare against baseline externally).

        Parameters
        ----------
        response  : HTTPResponse to evaluate.
        technique : Single-char technique code.

        Returns
        -------
        bool
        """
        if response.error or response.status_code == 0:
            return False
        body = response.body.lower()
        tech = technique.upper()

        if tech == "E":
            return any(p in body for p in [
                "sql syntax", "mysql_fetch", "ora-01756", "sqlstate",
                "unclosed quotation", "unterminated string",
                "supplied argument is not a valid mysql",
                "warning: mysql", "mssql", "microsoft ole db",
                "odbc microsoft access",
            ])
        if tech == "T":
            return response.latency > 4.0
        if tech == "U":
            return any(m in body for m in ["jeevsql_marker", "null,null"])
        if tech == "B":
            return response.status_code == 200 and bool(response.body)
        return False

    @staticmethod
    def _default_headers() -> Dict[str, str]:
        """Return a minimal set of sane default HTTP request headers."""
        return {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            ),
            "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection":      "keep-alive",
            "Cache-Control":   "no-cache",
        }


# ── Context-manager wrapper ───────────────────────────────────────────────────

class ManagedScanEngine:
    """
    Async context manager for AsyncScanEngine.

    Example
    -------
    >>> async with ManagedScanEngine(max_concurrent=20) as engine:
    ...     result = await engine.scan_target(url, payloads, params, "E")
    """

    def __init__(self, **kwargs: Any) -> None:
        self._kw     = kwargs
        self._engine: Optional[AsyncScanEngine] = None

    async def __aenter__(self) -> AsyncScanEngine:
        self._engine = AsyncScanEngine(**self._kw)
        await self._engine.init()
        return self._engine

    async def __aexit__(self, *_: Any) -> None:
        if self._engine:
            await self._engine.close()


# ── Synchronous wrapper ───────────────────────────────────────────────────────

def run_scan(
    url:        str,
    payloads:   List[str],
    parameters: Dict[str, str],
    technique:  str = "B",
    **engine_kwargs: Any,
) -> ScanResult:
    """
    Synchronous convenience wrapper – runs an async scan from blocking code.

    Parameters
    ----------
    url           : Target URL.
    payloads      : Injection payload list.
    parameters    : Baseline parameter dict.
    technique     : Technique code.
    **engine_kwargs : Forwarded to AsyncScanEngine.

    Returns
    -------
    ScanResult
    """
    async def _inner() -> ScanResult:
        async with ManagedScanEngine(**engine_kwargs) as eng:
            return await eng.scan_target(url, payloads, parameters, technique)

    return asyncio.run(_inner())


# ── Self-test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    async def _demo() -> None:
        print("[GenSQL] async_engine self-test ...")
        async with ManagedScanEngine(max_concurrent=5, timeout=10) as eng:
            result = await eng.scan_target(
                url="https://httpbin.org/get",
                payloads=["' OR '1'='1", "' AND 1=1--"],
                parameters={"id": "1"},
                technique="E",
            )
        print(f"  vulnerable : {result.vulnerable}")
        print(f"  metrics    : {result.metrics}")
        print("[GenSQL] self-test complete.")

    asyncio.run(_demo())
