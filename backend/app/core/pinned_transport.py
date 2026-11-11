from __future__ import annotations

import contextlib
import ipaddress
import ssl
import time
from typing import Any, AsyncIterator, Iterable, Iterator, Optional

import httpcore
import httpx

from app.core.ssrf import (
    PinnedTarget,
    SSRFProtectionError,
    _canonicalize_allowed_ip,
    is_ip_allowed,
)

DEFAULT_PINNED_LIMITS = httpx.Limits(
    max_connections=1,
    max_keepalive_connections=0,
    keepalive_expiry=0.0,
)

# Public httpcore -> httpx exception translation map (ordered cleanly; most specific match wins).
_HTTPCORE_TO_HTTPX_EXCEPTIONS: tuple[tuple[type[BaseException], type[httpx.HTTPError]], ...] = (
    (httpcore.ConnectTimeout, httpx.ConnectTimeout),
    (httpcore.ReadTimeout, httpx.ReadTimeout),
    (httpcore.WriteTimeout, httpx.WriteTimeout),
    (httpcore.PoolTimeout, httpx.PoolTimeout),
    (httpcore.TimeoutException, httpx.TimeoutException),
    (httpcore.ConnectError, httpx.ConnectError),
    (httpcore.ReadError, httpx.ReadError),
    (httpcore.WriteError, httpx.WriteError),
    (httpcore.NetworkError, httpx.NetworkError),
    (httpcore.ProxyError, httpx.ProxyError),
    (httpcore.UnsupportedProtocol, httpx.UnsupportedProtocol),
    (httpcore.LocalProtocolError, httpx.LocalProtocolError),
    (httpcore.RemoteProtocolError, httpx.RemoteProtocolError),
    (httpcore.ProtocolError, httpx.ProtocolError),
)


@contextlib.contextmanager
def _map_httpcore_exceptions() -> Iterator[None]:
    """Translate public httpcore exceptions to httpx equivalents, preserving SSRFProtectionError."""
    try:
        yield
    except SSRFProtectionError:
        raise
    except Exception as exc:
        mapped_exc: Optional[type[httpx.HTTPError]] = None
        for from_exc, to_exc in _HTTPCORE_TO_HTTPX_EXCEPTIONS:
            if isinstance(exc, from_exc):
                if mapped_exc is None or issubclass(to_exc, mapped_exc):
                    mapped_exc = to_exc
        if mapped_exc is None:
            raise
        raise mapped_exc(str(exc)) from exc


def resolve_verified_ssl_context(ssl_context: Optional[ssl.SSLContext] = None) -> ssl.SSLContext:
    """
    Return a strictly verifying SSLContext.
    Production defaults to certifi via httpx.create_ssl_context(verify=True, trust_env=False).
    Custom contexts (e.g. test CA bundles) must preserve CERT_REQUIRED and check_hostname=True.
    """
    if ssl_context is None:
        return httpx.create_ssl_context(verify=True, trust_env=False)

    if not isinstance(ssl_context, ssl.SSLContext):
        raise ValueError("ssl_context must be an ssl.SSLContext instance or None.")

    if ssl_context.verify_mode != ssl.CERT_REQUIRED or not ssl_context.check_hostname:
        raise ValueError(
            "TLS certificate verification (CERT_REQUIRED) and hostname verification (check_hostname) must remain enabled."
        )

    return ssl_context


class PinnedNetworkStream(httpcore.AsyncNetworkStream):
    """Stream wrapper enforcing expected TLS server_hostname (SNI) parity."""

    def __init__(
        self,
        inner: httpcore.AsyncNetworkStream,
        expected_server_hostname: Optional[str] = None,
    ) -> None:
        self._inner = inner
        self._expected_server_hostname = (
            expected_server_hostname.lower() if expected_server_hostname else None
        )

    async def read(self, max_bytes: int, timeout: Optional[float] = None) -> bytes:
        return await self._inner.read(max_bytes, timeout=timeout)

    async def write(self, buffer: bytes, timeout: Optional[float] = None) -> None:
        await self._inner.write(buffer, timeout=timeout)

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> httpcore.AsyncNetworkStream:
        resolve_verified_ssl_context(ssl_context)
        if self._expected_server_hostname is not None:
            actual_sni = (server_hostname or "").lower().rstrip(".")
            if actual_sni != self._expected_server_hostname:
                raise SSRFProtectionError(
                    f"TLS server_hostname mismatch: expected '{self._expected_server_hostname}', got '{server_hostname}'."
                )
        wrapped = await self._inner.start_tls(
            ssl_context=ssl_context,
            server_hostname=server_hostname,
            timeout=timeout,
        )
        return PinnedNetworkStream(
            wrapped,
            expected_server_hostname=self._expected_server_hostname,
        )

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """
    httpcore AsyncNetworkBackend bound to an immutable PinnedTarget.

    Guarantees that TCP dials connect solely to pre-validated IP literals without
    performing a second OS DNS lookup or falling back to hostname resolution.
    """

    def __init__(
        self,
        target: PinnedTarget,
        inner_backend: Optional[httpcore.AsyncNetworkBackend] = None,
    ) -> None:
        self._target = target
        self._inner = inner_backend if inner_backend is not None else httpcore.AnyIOBackend()
        self.attempted_ips: list[str] = []
        self.connected_ip: Optional[str] = None

    def _validate_target_match(self, host: str, port: int) -> None:
        if port != self._target.port:
            raise SSRFProtectionError(
                f"Pinned port mismatch: expected {self._target.port}, got {port}."
            )
        normalized_host = host.strip("[]").lower().rstrip(".")
        if self._target.is_ip_literal:
            try:
                if ipaddress.ip_address(normalized_host) == ipaddress.ip_address(self._target.host):
                    return
            except ValueError:
                pass
        if normalized_host != self._target.host:
            raise SSRFProtectionError(
                f"Pinned hostname mismatch: expected '{self._target.host}', got '{host}'."
            )

    def _validate_pinned_ips(self) -> tuple[str, ...]:
        if not self._target.pinned_ips:
            raise SSRFProtectionError(
                f"No validated IP addresses are pinned for '{self._target.host}'."
            )
        validated: list[str] = []
        for ip_str in self._target.pinned_ips:
            if not is_ip_allowed(ip_str, allow_internal=self._target.allow_internal):
                raise SSRFProtectionError(
                    f"Pinned IP address '{ip_str}' violates SSRF policy."
                )
            validated.append(_canonicalize_allowed_ip(ip_str))
        return tuple(validated)

    def _validate_connected_peer_addr(self, server_addr: Any, expected_ip: str) -> None:
        if not isinstance(server_addr, (tuple, list)) or len(server_addr) not in (2, 4):
            raise SSRFProtectionError(
                "Connected stream did not provide a valid peer socket address."
            )

        raw_ip = server_addr[0]
        raw_port = server_addr[1]
        if not isinstance(raw_ip, str) or not raw_ip.strip():
            raise SSRFProtectionError(
                "Connected stream returned an empty or malformed peer IP address."
            )
        if isinstance(raw_port, bool) or not isinstance(raw_port, int) or not (1 <= raw_port <= 65535):
            raise SSRFProtectionError(
                f"Connected stream returned a malformed peer port '{raw_port!r}'."
            )
        if raw_port != self._target.port:
            raise SSRFProtectionError(
                f"Connected peer port {raw_port} does not match pinned target port {self._target.port}."
            )

        if len(server_addr) == 4:
            scope_id = server_addr[3]
            if isinstance(scope_id, bool) or not isinstance(scope_id, int):
                raise SSRFProtectionError(
                    f"Connected stream returned a malformed IPv6 scope ID '{scope_id!r}'."
                )
            if scope_id != 0:
                raise SSRFProtectionError(
                    f"Connected peer IP '{raw_ip}' has forbidden non-zero scope ID {scope_id}."
                )

        if "%" in raw_ip:
            raise SSRFProtectionError(
                f"Connected peer IP '{raw_ip}' contains forbidden scope ID."
            )
        if not is_ip_allowed(raw_ip, allow_internal=self._target.allow_internal):
            raise SSRFProtectionError(
                f"Connected peer IP '{raw_ip}' violates SSRF policy."
            )
        try:
            canon_peer = _canonicalize_allowed_ip(raw_ip)
        except ValueError as exc:
            raise SSRFProtectionError(f"Invalid connected peer IP '{raw_ip}'.") from exc
        if canon_peer != expected_ip:
            raise SSRFProtectionError(
                f"Connected peer IP '{canon_peer}' does not match pinned IP '{expected_ip}'."
            )

    async def _verify_connected_peer(
        self,
        stream: httpcore.AsyncNetworkStream,
        expected_ip: str,
    ) -> None:
        server_addr = stream.get_extra_info("server_addr")
        try:
            self._validate_connected_peer_addr(server_addr, expected_ip)
        except Exception:
            try:
                await stream.aclose()
            except Exception:
                pass
            raise

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Iterable[httpcore.SOCKET_OPTION]] = None,
    ) -> httpcore.AsyncNetworkStream:
        self._validate_target_match(host, port)
        candidate_ips = self._validate_pinned_ips()

        deadline = (time.monotonic() + float(timeout)) if timeout is not None else None
        last_error: Optional[Exception] = None

        for idx, candidate_ip in enumerate(candidate_ips):
            per_attempt_timeout: Optional[float] = None
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise httpcore.ConnectTimeout(
                        f"Timed out connecting to pinned address(es) for '{self._target.host}:{port}'."
                    )
                remaining_attempts = len(candidate_ips) - idx
                per_attempt_timeout = remaining / remaining_attempts

            self.attempted_ips.append(candidate_ip)
            try:
                stream = await self._inner.connect_tcp(
                    host=candidate_ip,
                    port=port,
                    timeout=per_attempt_timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectTimeout, httpcore.ConnectError) as exc:
                last_error = exc
                continue

            await self._verify_connected_peer(stream, candidate_ip)
            self.connected_ip = candidate_ip
            expected_sni = self._target.host if self._target.scheme == "https" else None
            return PinnedNetworkStream(stream, expected_server_hostname=expected_sni)

        if last_error is not None:
            raise last_error
        raise httpcore.ConnectError(
            f"All pinned connection attempts failed for '{self._target.host}:{port}'."
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: Optional[float] = None,
        socket_options: Optional[Iterable[httpcore.SOCKET_OPTION]] = None,
    ) -> httpcore.AsyncNetworkStream:
        raise SSRFProtectionError("Unix domain socket connections are forbidden by SSRF policy.")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class _PinnedAsyncResponseStream(httpx.AsyncByteStream):
    """Wraps httpcore response stream to preserve resource cleanup and exception mapping."""

    def __init__(self, httpcore_stream: Any) -> None:
        self._httpcore_stream = httpcore_stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        with _map_httpcore_exceptions():
            async for chunk in self._httpcore_stream:
                yield chunk

    async def aclose(self) -> None:
        if hasattr(self._httpcore_stream, "aclose"):
            with _map_httpcore_exceptions():
                await self._httpcore_stream.aclose()


class PinnedAsyncHTTPTransport(httpx.AsyncBaseTransport):
    """
    Ephemeral httpx AsyncBaseTransport backed by httpcore.AsyncConnectionPool
    using PinnedNetworkBackend with cross-request pooling disabled.
    """

    def __init__(
        self,
        target: PinnedTarget,
        *,
        ssl_context: Optional[ssl.SSLContext] = None,
        limits: httpx.Limits = DEFAULT_PINNED_LIMITS,
        http1: bool = True,
        http2: bool = False,
        inner_backend: Optional[httpcore.AsyncNetworkBackend] = None,
    ) -> None:
        self._target = target
        self._ssl_context = resolve_verified_ssl_context(ssl_context)
        self.network_backend = PinnedNetworkBackend(target, inner_backend=inner_backend)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=self._ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            http1=http1,
            http2=http2,
            retries=0,
            network_backend=self.network_backend,
        )

    def _assert_request_matches_target(self, request: httpx.Request) -> None:
        req_scheme = request.url.scheme.lower()
        req_host = request.url.raw_host.decode("ascii").lower()
        default_port = 443 if req_scheme == "https" else 80
        req_port = request.url.port if request.url.port is not None else default_port
        if (
            req_scheme != self._target.scheme
            or req_host != self._target.host
            or req_port != self._target.port
        ):
            raise SSRFProtectionError(
                f"Request target '{req_scheme}://{req_host}:{req_port}' does not match pinned target "
                f"'{self._target.scheme}://{self._target.host}:{self._target.port}'."
            )

    async def __aenter__(self) -> "PinnedAsyncHTTPTransport":
        await self._pool.__aenter__()
        return self

    async def __aexit__(self, exc_type: Any = None, exc_value: Any = None, traceback: Any = None) -> None:
        with _map_httpcore_exceptions():
            await self._pool.__aexit__(exc_type, exc_value, traceback)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if not isinstance(request.stream, httpx.AsyncByteStream):
            raise RuntimeError("PinnedAsyncHTTPTransport requires an async request stream.")

        self._assert_request_matches_target(request)
        core_req = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        with _map_httpcore_exceptions():
            core_resp = await self._pool.handle_async_request(core_req)

        return httpx.Response(
            status_code=core_resp.status,
            headers=core_resp.headers,
            stream=_PinnedAsyncResponseStream(core_resp.stream),
            extensions=core_resp.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()
