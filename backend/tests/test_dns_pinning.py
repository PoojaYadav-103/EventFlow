import asyncio
import http.server
import json
import os
import socket
import ssl
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpcore
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.core.config import settings
from app.core.pinned_transport import (
    DEFAULT_PINNED_LIMITS,
    PinnedAsyncHTTPTransport,
    PinnedNetworkBackend,
    resolve_verified_ssl_context,
)
from app.core.security import generate_signing_secret, verify_signature_detailed
from app.core.ssrf import (
    BoundedDNSResolver,
    DNSResolutionTimeoutError,
    PermanentDNSResolutionError,
    PinnedTarget,
    SSRFProtectionError,
    TransientDNSResolutionError,
    async_resolve_and_pin_target,
)
from app.models.delivery import Delivery, DeliveryStatus
from app.models.endpoint import Endpoint
from app.models.event import Event
from app.services.delivery_service import DeliveryService
from app.services.webhook_client import HTTPOutcome, execute_webhook_request


def _gai_entry(ip: str, port: int = 0) -> Tuple[int, int, int, str, Tuple[Any, ...]]:
    """Build a realistic socket.getaddrinfo 5-tuple for an IPv4 or IPv6 literal."""
    if ":" in ip:
        return (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port, 0, 0))
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))


def _build_ephemeral_pki(tmp_path) -> Tuple[str, Callable[..., Tuple[str, str]]]:
    """Create an in-memory ephemeral CA and signed leaf cert issuer in tmp_path."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EventFlow Test Root CA")])
    now = datetime.now(timezone.utc)
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(ca_ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    counter = 0

    def issue_leaf(
        dns_names: Optional[List[str]] = None,
        ip_addresses: Optional[List[str]] = None,
        common_name: Optional[str] = None,
    ) -> Tuple[str, str]:
        nonlocal counter
        counter += 1
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cn = common_name or (dns_names[0] if dns_names else "127.0.0.1")
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

        san_entries: List[x509.GeneralName] = []
        for dns_name in dns_names or []:
            san_entries.append(x509.DNSName(dns_name))
        import ipaddress as _ipaddress

        for ip_val in ip_addresses or []:
            san_entries.append(x509.IPAddress(_ipaddress.ip_address(ip_val)))

        builder = (
            x509.CertificateBuilder()
            .subject_name(leaf_name)
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
        )
        if san_entries:
            builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

        leaf_cert = builder.sign(ca_key, hashes.SHA256())
        cert_path = tmp_path / f"leaf_{counter}.crt.pem"
        key_path = tmp_path / f"leaf_{counter}.key.pem"
        cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            leaf_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        return str(cert_path), str(key_path)

    return ca_pem, issue_leaf


class _QuietThreadingHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address) -> None:
        # Ignore expected TLS handshake aborts from negative certificate verification tests.
        return


class _LocalWebhookServer:
    """Context-managed local HTTP/HTTPS server on 127.0.0.1 for integration tests."""

    def __init__(
        self,
        ssl_context: Optional[ssl.SSLContext] = None,
        response_body: bytes = b'{"received": true}',
        response_status: int = 200,
    ) -> None:
        self.requests: List[Dict[str, Any]] = []
        self.sni_names: List[Optional[str]] = []
        self._response_body = response_body
        self._response_status = response_status
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or 0)
                body = self.rfile.read(length) if length > 0 else b""
                headers_lower = {k.lower(): v for k, v in self.headers.items()}
                parent.requests.append(
                    {
                        "path": self.path,
                        "host": self.headers.get("Host"),
                        "headers": headers_lower,
                        "body": body,
                    }
                )
                self.send_response(parent._response_status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(parent._response_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(parent._response_body)

        self._server = _QuietThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if ssl_context is not None:
            def _capture_sni(ssl_sock, server_name, ctx):
                parent.sni_names.append(server_name)

            ssl_context.sni_callback = _capture_sni
            self._server.socket = ssl_context.wrap_socket(self._server.socket, server_side=True)

        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "_LocalWebhookServer":
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2.0)


_UNSET = object()


class _InMemoryHTTPStream(httpcore.AsyncNetworkStream):
    """Minimal in-memory HTTP/1.1 stream for deterministic backend & IPv6 tests."""

    def __init__(
        self,
        server_ip: str,
        port: int,
        body: bytes = b'{"ok": true}',
        override_server_addr: Any = _UNSET,
        captured_requests: Optional[List[bytes]] = None,
    ) -> None:
        self._server_ip = server_ip
        self._port = port
        self._body = body
        self._override_server_addr = override_server_addr
        self._captured_requests = captured_requests
        self._buf = bytearray()
        self._request_complete = asyncio.Event()
        self._response_sent = False
        self.closed = False

    def _is_full_http_request(self) -> bool:
        sep = self._buf.find(b"\r\n\r\n")
        if sep == -1:
            return False
        head = bytes(self._buf[:sep]).decode("latin-1")
        content_length = 0
        for line in head.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                if k.strip().lower() == "content-length":
                    content_length = int(v.strip())
        return len(self._buf) >= sep + 4 + content_length

    async def write(self, buffer: bytes, timeout: Optional[float] = None) -> None:
        self._buf.extend(buffer)
        if self._is_full_http_request():
            if self._captured_requests is not None:
                self._captured_requests.append(bytes(self._buf))
            self._request_complete.set()

    async def read(self, max_bytes: int, timeout: Optional[float] = None) -> bytes:
        await self._request_complete.wait()
        if self._response_sent:
            return b""
        self._response_sent = True
        payload = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(self._body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + self._body
        )
        return payload[:max_bytes]

    async def aclose(self) -> None:
        self.closed = True

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> httpcore.AsyncNetworkStream:
        return self

    def get_extra_info(self, info: str) -> Any:
        if info == "server_addr":
            if self._override_server_addr is not _UNSET:
                return self._override_server_addr
            if ":" in self._server_ip:
                return (self._server_ip, self._port, 0, 0)
            return (self._server_ip, self._port)
        return None


class _InMemoryHTTPBackend(httpcore.AsyncNetworkBackend):
    """Fake AsyncNetworkBackend recording exact TCP dials without touching OS sockets."""

    def __init__(
        self,
        fail_ips: Optional[set[str]] = None,
        response_by_ip: Optional[Dict[str, bytes]] = None,
        override_server_addr: Any = _UNSET,
    ) -> None:
        self.fail_ips = fail_ips or set()
        self.response_by_ip = response_by_ip or {}
        self.override_server_addr = override_server_addr
        self.connect_calls: List[Tuple[str, int]] = []
        self.captured_requests: List[bytes] = []
        self.streams: List[_InMemoryHTTPStream] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Any] = None,
    ) -> httpcore.AsyncNetworkStream:
        self.connect_calls.append((host, port))
        if host in self.fail_ips:
            raise httpcore.ConnectError(f"Simulated connection refusal to {host}:{port}")
        body = self.response_by_ip.get(host, b'{"ok": true}')
        stream = _InMemoryHTTPStream(
            server_ip=host,
            port=port,
            body=body,
            override_server_addr=self.override_server_addr,
            captured_requests=self.captured_requests,
        )
        self.streams.append(stream)
        return stream

    async def connect_unix_socket(
        self,
        path: str,
        timeout: Optional[float] = None,
        socket_options: Optional[Any] = None,
    ) -> httpcore.AsyncNetworkStream:
        raise AssertionError("connect_unix_socket must never be invoked")

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


# ---------------------------------------------------------------------------
# 1. Transport construction, httpcore/httpx compatibility, TLS & backend guards
# ---------------------------------------------------------------------------


def test_httpcore_and_httpx_transport_construction_and_tls_guards() -> None:
    target = PinnedTarget(
        normalized_url="https://hooks.example.test/webhook",
        scheme="https",
        host="hooks.example.test",
        port=443,
        pinned_ips=("93.184.216.34",),
        is_ip_literal=False,
        allow_internal=False,
    )

    assert DEFAULT_PINNED_LIMITS.max_connections == 1
    assert DEFAULT_PINNED_LIMITS.max_keepalive_connections == 0
    assert DEFAULT_PINNED_LIMITS.keepalive_expiry == 0.0

    default_ctx = resolve_verified_ssl_context(None)
    assert default_ctx.verify_mode == ssl.CERT_REQUIRED
    assert default_ctx.check_hostname is True

    transport = PinnedAsyncHTTPTransport(target=target)
    assert isinstance(transport, httpx.AsyncBaseTransport)

    asyncio.run(transport.aclose())

    no_verify_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    no_verify_ctx.check_hostname = False
    no_verify_ctx.verify_mode = ssl.CERT_NONE
    with pytest.raises(ValueError):
        resolve_verified_ssl_context(no_verify_ctx)
    with pytest.raises(ValueError):
        PinnedAsyncHTTPTransport(target=target, ssl_context=no_verify_ctx)

    no_hostname_ctx = ssl.create_default_context()
    no_hostname_ctx.check_hostname = False
    with pytest.raises(ValueError):
        resolve_verified_ssl_context(no_hostname_ctx)
    with pytest.raises(ValueError):
        PinnedAsyncHTTPTransport(target=target, ssl_context=no_hostname_ctx)


@pytest.mark.asyncio
async def test_pinned_backend_and_transport_enforce_pinning_invariants() -> None:
    target = PinnedTarget(
        normalized_url="http://pinned.example.test:8080/hook",
        scheme="http",
        host="pinned.example.test",
        port=8080,
        pinned_ips=("93.184.216.34",),
        is_ip_literal=False,
        allow_internal=False,
    )

    spoof_backend = _InMemoryHTTPBackend(override_server_addr=("169.254.169.254", 8080))
    backend = PinnedNetworkBackend(target=target, inner_backend=spoof_backend)

    # Unix socket connections must always be forbidden.
    with pytest.raises(SSRFProtectionError, match="Unix domain socket"):
        await backend.connect_unix_socket("/var/run/docker.sock")

    # Cross-host or cross-port dials must be refused immediately.
    with pytest.raises(SSRFProtectionError, match="hostname"):
        await backend.connect_tcp("other.example.test", 8080)
    with pytest.raises(SSRFProtectionError, match="port"):
        await backend.connect_tcp("pinned.example.test", 9090)

    # Post-connect server_addr mismatch must close the stream and abort.
    with pytest.raises(SSRFProtectionError, match="169.254.169.254"):
        await backend.connect_tcp("pinned.example.test", 8080)
    assert len(spoof_backend.streams) == 1
    assert spoof_backend.streams[0].closed is True

    # Transport rejects requests targeting any mismatched scheme/host/port.
    good_backend = _InMemoryHTTPBackend()
    async with PinnedAsyncHTTPTransport(target=target, inner_backend=good_backend) as transport:
        bad_req = httpx.Request("POST", "http://evil.example.test:8080/hook", content=b"{}")
        with pytest.raises(SSRFProtectionError):
            await transport.handle_async_request(bad_req)
        assert good_backend.connect_calls == []


@pytest.mark.parametrize(
    "bad_server_addr",
    [
        None,
        (),
        [],
        "93.184.216.34",
        ("93.184.216.34",),
        ("", 8080),
        (None, 8080),
        ("93.184.216.34", "8080"),
        ("93.184.216.34", True),
        ("93.184.216.34", 0),
        ("93.184.216.34", 65536),
        ("93.184.216.34", 8080, 0),
        ("93.184.216.34", 8080, 0, 0, 0),
        ("93.184.216.34", 9090),
        ("93.184.216.35", 8080),
    ],
)
@pytest.mark.asyncio
async def test_verify_connected_peer_fails_closed_and_closes_stream_ipv4(
    bad_server_addr: Any,
) -> None:
    target = PinnedTarget(
        normalized_url="http://pinned.example.test:8080/hook",
        scheme="http",
        host="pinned.example.test",
        port=8080,
        pinned_ips=("93.184.216.34",),
        is_ip_literal=False,
        allow_internal=False,
    )
    inner = _InMemoryHTTPBackend(override_server_addr=bad_server_addr)
    backend = PinnedNetworkBackend(target=target, inner_backend=inner)

    with pytest.raises(SSRFProtectionError):
        await backend.connect_tcp("pinned.example.test", 8080)

    assert len(inner.streams) == 1
    assert inner.streams[0].closed is True
    assert backend.connected_ip is None


@pytest.mark.parametrize(
    "bad_ipv6_addr",
    [
        ("2606:4700:4700::1111", 8080, 0, 3),
        ("fe80::1", 8080, 0, 12),
        ("2606:4700:4700::1111", 8080, 0, "eth0"),
        ("2606:4700:4700::1111", 8080, 0, True),
        ("2606:4700:4700::2222", 8080, 0, 0),
        ("2606:4700:4700::1111", 8443, 0, 0),
    ],
)
@pytest.mark.asyncio
async def test_verify_connected_peer_rejects_nonzero_scope_id_and_ipv6_mismatches(
    bad_ipv6_addr: Tuple[Any, ...],
) -> None:
    allow_internal = str(bad_ipv6_addr[0]).startswith("fe80:")
    pinned_ip = "fe80::1" if allow_internal else "2606:4700:4700::1111"
    target = PinnedTarget(
        normalized_url="http://v6peer.example.test:8080/hook",
        scheme="http",
        host="v6peer.example.test",
        port=8080,
        pinned_ips=(pinned_ip,),
        is_ip_literal=False,
        allow_internal=allow_internal,
    )
    inner = _InMemoryHTTPBackend(override_server_addr=bad_ipv6_addr)
    backend = PinnedNetworkBackend(target=target, inner_backend=inner)

    with pytest.raises(SSRFProtectionError):
        await backend.connect_tcp("v6peer.example.test", 8080)

    assert len(inner.streams) == 1
    assert inner.streams[0].closed is True
    assert backend.connected_ip is None


def test_delivery_marks_missing_or_mismatched_peer_addr_permanent_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *args, **kwargs: [_gai_entry("93.184.216.34")],
    )

    for bad_addr in (None, ("93.184.216.34", 9090), ("2606:4700:4700::1111", 8080, 0, 2)):
        fake_backend = _InMemoryHTTPBackend(override_server_addr=bad_addr)
        monkeypatch.setattr(httpcore, "AnyIOBackend", lambda *args, _b=fake_backend, **kwargs: _b)

        res = execute_webhook_request(
            url="http://peercheck.example.test:8080/hook",
            secret=generate_signing_secret(),
            event_id="evt_peer_fail",
            delivery_id="del_peer_fail",
            event_type="test.peer",
            payload={"x": 1},
            allow_internal=False,
        )
        assert res.outcome == HTTPOutcome.PERMANENT_FAILURE
        assert len(fake_backend.streams) == 1
        assert fake_backend.streams[0].closed is True


# ---------------------------------------------------------------------------
# 2. DNS Rebinding TOCTOU simulation & IP pinning verification
# ---------------------------------------------------------------------------


def test_dns_rebinding_toctou_pins_first_ip_and_blocks_subsequent_rebind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dns_answers = [
        [_gai_entry("127.0.0.1")],
        [_gai_entry("169.254.169.254")],
        [_gai_entry("10.0.0.5")],
    ]
    getaddrinfo_calls: List[str] = []

    def fake_getaddrinfo(host: str, port: Any, *args: Any, **kwargs: Any):
        getaddrinfo_calls.append(host)
        idx = min(len(getaddrinfo_calls) - 1, len(dns_answers) - 1)
        return dns_answers[idx]

    connect_hosts: List[str] = []
    orig_connect_tcp = httpcore.AnyIOBackend.connect_tcp

    async def spy_connect_tcp(self, host: str, port: int, *args: Any, **kwargs: Any):
        connect_hosts.append(host)
        return await orig_connect_tcp(self, host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", spy_connect_tcp)

    with _LocalWebhookServer() as server:
        secret = generate_signing_secret()
        url = f"http://rebind.example.test:{server.port}/webhook"

        # Delivery #1 with allow_internal=True resolves 127.0.0.1 once and pins TCP to 127.0.0.1.
        res1 = execute_webhook_request(
            url=url,
            secret=secret,
            event_id="evt_1",
            delivery_id="del_1",
            event_type="order.placed",
            payload={"step": 1},
            allow_internal=True,
        )
        assert res1.outcome == HTTPOutcome.SUCCESS
        assert res1.http_status == 200
        assert len(getaddrinfo_calls) == 1
        assert connect_hosts == ["127.0.0.1"]

        # Delivery #2 sees DNS flipped to cloud metadata -> blocked before TCP connect.
        res2 = execute_webhook_request(
            url=url,
            secret=secret,
            event_id="evt_2",
            delivery_id="del_2",
            event_type="order.placed",
            payload={"step": 2},
            allow_internal=True,
        )
        assert res2.outcome == HTTPOutcome.PERMANENT_FAILURE
        assert "blocked" in (res2.error_message or "").lower()
        assert len(getaddrinfo_calls) == 2
        assert connect_hosts == ["127.0.0.1"]  # No new TCP dial occurred!

        # Delivery #3 with allow_internal=False sees DNS flipped to RFC1918 private -> blocked.
        res3 = execute_webhook_request(
            url=url,
            secret=secret,
            event_id="evt_3",
            delivery_id="del_3",
            event_type="order.placed",
            payload={"step": 3},
            allow_internal=False,
        )
        assert res3.outcome == HTTPOutcome.PERMANENT_FAILURE
        assert len(getaddrinfo_calls) == 3
        assert connect_hosts == ["127.0.0.1"]


def test_connect_tcp_uses_pinned_ip_preserves_host_header_and_validates_hmac(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dialed_hosts: List[str] = []
    orig_connect_tcp = httpcore.AnyIOBackend.connect_tcp

    async def spy_connect_tcp(self, host: str, port: int, *args: Any, **kwargs: Any):
        dialed_hosts.append(host)
        return await orig_connect_tcp(self, host, port, *args, **kwargs)

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *args, **kwargs: [_gai_entry("127.0.0.1")],
    )
    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", spy_connect_tcp)

    with _LocalWebhookServer() as server:
        secret = generate_signing_secret()
        url = f"http://hooks.partner-domain.test:{server.port}/v1/events?env=prod&v=2"
        payload = {"order_id": "ord_99", "amount": 4200}

        result = execute_webhook_request(
            url=url,
            secret=secret,
            event_id="evt_pin_1",
            delivery_id="del_pin_1",
            event_type="invoice.paid",
            payload=payload,
            allow_internal=True,
        )

        assert result.outcome == HTTPOutcome.SUCCESS
        assert result.http_status == 200
        assert dialed_hosts == ["127.0.0.1"]
        assert "hooks.partner-domain.test" not in dialed_hosts

        assert len(server.requests) == 1
        req = server.requests[0]
        assert req["host"] == f"hooks.partner-domain.test:{server.port}"
        assert req["path"] == "/v1/events?env=prod&v=2"

        verify_result = verify_signature_detailed(
            secret=secret,
            payload=req["body"],
            header_value=req["headers"]["x-eventflow-signature"],
            tolerance_seconds=300,
            auxiliary_timestamp_header=req["headers"].get("x-eventflow-timestamp"),
        )
        assert verify_result.is_valid is True
        assert json.loads(req["body"].decode("utf-8")) == payload


# ---------------------------------------------------------------------------
# 3. TLS SNI & certificate hostname verification when connecting to pinned IP
# ---------------------------------------------------------------------------


def test_tls_sni_and_certificate_hostname_verification_on_pinned_ip(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ca_pem, issue_leaf = _build_ephemeral_pki(tmp_path)
    secret = generate_signing_secret()

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *args, **kwargs: [_gai_entry("127.0.0.1")],
    )

    dialed_hosts: List[str] = []
    orig_connect_tcp = httpcore.AnyIOBackend.connect_tcp

    async def spy_connect_tcp(self, host: str, port: int, *args: Any, **kwargs: Any):
        dialed_hosts.append(host)
        return await orig_connect_tcp(self, host, port, *args, **kwargs)

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", spy_connect_tcp)

    # Case A: Leaf cert has DNS SAN "webhook.example.test" and NO IP SAN 127.0.0.1.
    cert_good, key_good = issue_leaf(dns_names=["webhook.example.test"], ip_addresses=[])
    server_ssl_good = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ssl_good.load_cert_chain(certfile=cert_good, keyfile=key_good)

    client_ctx = ssl.create_default_context(cadata=ca_pem)
    assert client_ctx.verify_mode == ssl.CERT_REQUIRED
    assert client_ctx.check_hostname is True

    with _LocalWebhookServer(ssl_context=server_ssl_good) as tls_server:
        res_good = execute_webhook_request(
            url=f"https://webhook.example.test:{tls_server.port}/hook",
            secret=secret,
            event_id="evt_tls_ok",
            delivery_id="del_tls_ok",
            event_type="tls.test",
            payload={"ok": True},
            allow_internal=True,
            ssl_context=client_ctx,
        )
        assert res_good.outcome == HTTPOutcome.SUCCESS
        assert res_good.http_status == 200
        assert dialed_hosts == ["127.0.0.1"]
        assert tls_server.sni_names == ["webhook.example.test"]
        assert tls_server.requests[0]["host"] == f"webhook.example.test:{tls_server.port}"

        # Case D: Untrusted CA (default client SSLContext) -> PERMANENT_FAILURE.
        res_untrusted = execute_webhook_request(
            url=f"https://webhook.example.test:{tls_server.port}/hook",
            secret=secret,
            event_id="evt_tls_untrusted",
            delivery_id="del_tls_untrusted",
            event_type="tls.test",
            payload={"ok": False},
            allow_internal=True,
            ssl_context=None,
        )
        assert res_untrusted.outcome == HTTPOutcome.PERMANENT_FAILURE
        assert "certificate" in (res_untrusted.error_message or "").lower()

    # Case B: Leaf cert has wrong DNS SAN -> PERMANENT_FAILURE.
    cert_wrong, key_wrong = issue_leaf(dns_names=["wrong.example.test"], ip_addresses=[])
    server_ssl_wrong = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ssl_wrong.load_cert_chain(certfile=cert_wrong, keyfile=key_wrong)

    with _LocalWebhookServer(ssl_context=server_ssl_wrong) as wrong_server:
        res_wrong = execute_webhook_request(
            url=f"https://webhook.example.test:{wrong_server.port}/hook",
            secret=secret,
            event_id="evt_tls_wrong",
            delivery_id="del_tls_wrong",
            event_type="tls.test",
            payload={"ok": False},
            allow_internal=True,
            ssl_context=client_ctx,
        )
        assert res_wrong.outcome == HTTPOutcome.PERMANENT_FAILURE
        assert "certificate" in (res_wrong.error_message or "").lower()

    # Case C: Leaf cert has ONLY IP SAN 127.0.0.1 (missing DNS SAN webhook.example.test) -> PERMANENT_FAILURE.
    cert_ip_only, key_ip_only = issue_leaf(
        dns_names=[],
        ip_addresses=["127.0.0.1"],
        common_name="127.0.0.1",
    )
    server_ssl_ip_only = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ssl_ip_only.load_cert_chain(certfile=cert_ip_only, keyfile=key_ip_only)

    with _LocalWebhookServer(ssl_context=server_ssl_ip_only) as ip_server:
        res_ip_only = execute_webhook_request(
            url=f"https://webhook.example.test:{ip_server.port}/hook",
            secret=secret,
            event_id="evt_tls_ip_only",
            delivery_id="del_tls_ip_only",
            event_type="tls.test",
            payload={"ok": False},
            allow_internal=True,
            ssl_context=client_ctx,
        )
        assert res_ip_only.outcome == HTTPOutcome.PERMANENT_FAILURE
        assert "certificate" in (res_ip_only.error_message or "").lower()


# ---------------------------------------------------------------------------
# 4. Mixed public/private DNS, dynamic metadata, and Docker mock receiver
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mixed_ips",
    [
        ["93.184.216.34", "10.0.0.5"],
        ["93.184.216.34", "100.64.0.1"],
        ["93.184.216.34", "::ffff:169.254.169.254"],
    ],
)
def test_mixed_public_and_private_dns_answers_rejected_before_tcp_connect(
    mixed_ips: List[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *args, **kwargs: [_gai_entry(ip) for ip in mixed_ips],
    )
    tcp_calls: List[Tuple[str, int]] = []

    async def spy_connect_tcp(self, host: str, port: int, *args: Any, **kwargs: Any):
        tcp_calls.append((host, port))
        raise AssertionError("connect_tcp must not be called for mixed public/private DNS")

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", spy_connect_tcp)

    with pytest.raises(SSRFProtectionError):
        asyncio.run(async_resolve_and_pin_target("https://mixed.example.test/hook", allow_internal=False))

    result = execute_webhook_request(
        url="https://mixed.example.test/hook",
        secret=generate_signing_secret(),
        event_id="evt_mix",
        delivery_id="del_mix",
        event_type="test.mixed",
        payload={"a": 1},
        allow_internal=False,
    )
    assert result.outcome == HTTPOutcome.PERMANENT_FAILURE
    assert tcp_calls == []


@pytest.mark.parametrize(
    "metadata_ips",
    [
        ["169.254.169.254"],
        ["100.100.100.200"],
        ["127.0.0.1", "169.254.169.254"],
        ["::ffff:169.254.169.254"],
    ],
)
def test_dynamic_metadata_blocked_even_with_allow_internal_networks_true(
    metadata_ips: List[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "ALLOW_INTERNAL_NETWORKS", True)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *args, **kwargs: [_gai_entry(ip) for ip in metadata_ips],
    )
    tcp_calls: List[Tuple[str, int]] = []

    async def spy_connect_tcp(self, host: str, port: int, *args: Any, **kwargs: Any):
        tcp_calls.append((host, port))
        raise AssertionError("connect_tcp must never dial metadata targets")

    monkeypatch.setattr(httpcore.AnyIOBackend, "connect_tcp", spy_connect_tcp)

    result = execute_webhook_request(
        url="https://meta-rebind.example.test/hook",
        secret=generate_signing_secret(),
        event_id="evt_meta",
        delivery_id="del_meta",
        event_type="test.meta",
        payload={"m": 1},
        allow_internal=True,
    )
    assert result.outcome == HTTPOutcome.PERMANENT_FAILURE
    assert tcp_calls == []


@pytest.mark.parametrize("mock_host", ["backend", "localhost", "127.0.0.1"])
def test_docker_mock_receiver_urls_compatible_with_allow_internal_true(
    mock_host: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "ALLOW_INTERNAL_NETWORKS", True)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *args, **kwargs: [_gai_entry("127.0.0.1")],
    )

    with _LocalWebhookServer() as server:
        url = f"http://{mock_host}:{server.port}/api/v1/mock-receiver"
        result = execute_webhook_request(
            url=url,
            secret=generate_signing_secret(),
            event_id=f"evt_{mock_host}",
            delivery_id=f"del_{mock_host}",
            event_type="test.docker",
            payload={"host": mock_host},
            allow_internal=True,
        )
        assert result.outcome == HTTPOutcome.SUCCESS
        assert result.http_status == 200
        assert server.requests[0]["host"] == f"{mock_host}:{server.port}"
        assert server.requests[0]["path"] == "/api/v1/mock-receiver"


# ---------------------------------------------------------------------------
# 5. Multi-IP fallback without secondary DNS & pooling isolation
# ---------------------------------------------------------------------------


def test_multi_ip_fallback_uses_only_validated_ips_without_second_dns_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dns_calls: List[str] = []

    def fake_getaddrinfo(host: str, port: Any, *args: Any, **kwargs: Any):
        dns_calls.append(host)
        return [
            _gai_entry("93.184.216.10"),
            _gai_entry("93.184.216.11"),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    backend_ok = _InMemoryHTTPBackend(fail_ips={"93.184.216.10"})
    monkeypatch.setattr(httpcore, "AnyIOBackend", lambda *args, **kwargs: backend_ok)

    res_fallback = execute_webhook_request(
        url="http://multi.example.test:8080/hook",
        secret=generate_signing_secret(),
        event_id="evt_multi_1",
        delivery_id="del_multi_1",
        event_type="test.multi",
        payload={"n": 1},
        allow_internal=False,
    )
    assert res_fallback.outcome == HTTPOutcome.SUCCESS
    assert res_fallback.http_status == 200
    assert dns_calls == ["multi.example.test"]
    assert backend_ok.connect_calls == [
        ("93.184.216.10", 8080),
        ("93.184.216.11", 8080),
    ]

    # When every pinned IP fails, fail as RETRYABLE_FAILURE with zero extra DNS lookups.
    backend_all_fail = _InMemoryHTTPBackend(fail_ips={"93.184.216.10", "93.184.216.11"})
    monkeypatch.setattr(httpcore, "AnyIOBackend", lambda *args, **kwargs: backend_all_fail)

    res_all_fail = execute_webhook_request(
        url="http://multi.example.test:8080/hook",
        secret=generate_signing_secret(),
        event_id="evt_multi_2",
        delivery_id="del_multi_2",
        event_type="test.multi",
        payload={"n": 2},
        allow_internal=False,
    )
    assert res_all_fail.outcome == HTTPOutcome.RETRYABLE_FAILURE
    assert dns_calls == ["multi.example.test", "multi.example.test"]
    assert backend_all_fail.connect_calls == [
        ("93.184.216.10", 8080),
        ("93.184.216.11", 8080),
    ]


def test_no_connection_pool_reuse_across_deliveries_when_dns_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dns_sequence = [
        [_gai_entry("93.184.216.10")],
        [_gai_entry("93.184.216.20")],
        [_gai_entry("10.0.0.8")],
    ]
    call_idx = 0

    def fake_getaddrinfo(host: str, port: Any, *args: Any, **kwargs: Any):
        nonlocal call_idx
        result = dns_sequence[call_idx]
        call_idx += 1
        return result

    shared_backend = _InMemoryHTTPBackend(
        response_by_ip={
            "93.184.216.10": b'{"server": "A"}',
            "93.184.216.20": b'{"server": "B"}',
        }
    )
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(httpcore, "AnyIOBackend", lambda *args, **kwargs: shared_backend)

    secret = generate_signing_secret()
    url = "http://pool.example.test:8080/hook"

    r1 = execute_webhook_request(url, secret, "e1", "d1", "evt", {"i": 1}, allow_internal=False)
    r2 = execute_webhook_request(url, secret, "e2", "d2", "evt", {"i": 2}, allow_internal=False)
    r3 = execute_webhook_request(url, secret, "e3", "d3", "evt", {"i": 3}, allow_internal=False)

    assert r1.outcome == HTTPOutcome.SUCCESS
    assert r1.response_body == '{"server": "A"}'
    assert r2.outcome == HTTPOutcome.SUCCESS
    assert r2.response_body == '{"server": "B"}'
    assert r3.outcome == HTTPOutcome.PERMANENT_FAILURE
    assert shared_backend.connect_calls == [
        ("93.184.216.10", 8080),
        ("93.184.216.20", 8080),
    ]


# ---------------------------------------------------------------------------
# 6. IPv6 pinning, DNS timeout & concurrency bounds, and error classification
# ---------------------------------------------------------------------------


def test_ipv6_pinning_and_scoped_ipv6_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Scoped IPv6 link-local addresses must always fail validation even when allow_internal=True.
    with pytest.raises(SSRFProtectionError):
        asyncio.run(async_resolve_and_pin_target("http://[fe80::1%25eth0]:8080/hook", allow_internal=True))

    # IPv6 literal pin preserves canonical address.
    target_literal = asyncio.run(async_resolve_and_pin_target("http://[::1]:8080/hook", allow_internal=True))
    assert target_literal.pinned_ips == ("::1",)
    assert target_literal.is_ip_literal is True

    # AAAA resolution pins global unicast IPv6 and dispatches using Host without brackets mismatch.
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *args, **kwargs: [_gai_entry("2606:4700:4700::1111")],
    )
    v6_backend = _InMemoryHTTPBackend()
    monkeypatch.setattr(httpcore, "AnyIOBackend", lambda *args, **kwargs: v6_backend)

    res = execute_webhook_request(
        url="http://v6.example.test:8080/hook",
        secret=generate_signing_secret(),
        event_id="evt_v6",
        delivery_id="del_v6",
        event_type="test.v6",
        payload={"v6": True},
        allow_internal=False,
    )
    assert res.outcome == HTTPOutcome.SUCCESS
    assert v6_backend.connect_calls == [("2606:4700:4700::1111", 8080)]
    assert b"Host: v6.example.test:8080\r\n" in v6_backend.captured_requests[0]


def test_dns_timeout_aborts_within_deadline_and_bounded_resolver_saturation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unblock = threading.Event()
    try:
        def slow_getaddrinfo(host: str, port: Any, *args: Any, **kwargs: Any):
            unblock.wait(timeout=10.0)
            return [_gai_entry("93.184.216.34")]

        monkeypatch.setattr(socket, "getaddrinfo", slow_getaddrinfo)

        started = time.monotonic()
        result = execute_webhook_request(
            url="http://slow-dns.example.test/hook",
            secret=generate_signing_secret(),
            event_id="evt_dns_timeout",
            delivery_id="del_dns_timeout",
            event_type="test.timeout",
            payload={"slow": True},
            timeout_seconds=0.35,
            allow_internal=False,
        )
        elapsed = time.monotonic() - started

        assert result.outcome == HTTPOutcome.RETRYABLE_FAILURE
        assert "timed out" in (result.error_message or "").lower()
        assert elapsed < 2.0
    finally:
        unblock.set()

    # Verify BoundedDNSResolver semaphore bounds concurrent threads and recovers once drained.
    resolver = BoundedDNSResolver(max_workers=2)
    gate = threading.Event()
    entered_count = 0
    entered_lock = threading.Lock()
    two_entered = threading.Event()

    def blocked_fn(host: str, port: int):
        nonlocal entered_count
        with entered_lock:
            entered_count += 1
            if entered_count >= 2:
                two_entered.set()
        gate.wait(timeout=5.0)
        return [_gai_entry("93.184.216.34")]

    async def exercise_saturation():
        t1 = asyncio.create_task(resolver.resolve("h1.test", 443, timeout=5.0, resolver_fn=blocked_fn))
        t2 = asyncio.create_task(resolver.resolve("h2.test", 443, timeout=5.0, resolver_fn=blocked_fn))
        await asyncio.to_thread(two_entered.wait, 2.0)

        with pytest.raises(DNSResolutionTimeoutError):
            await resolver.resolve("h3.test", 443, timeout=0.15, resolver_fn=blocked_fn)
        assert entered_count == 2  # Third lookup never spawned an extra worker thread.

        gate.set()
        res1, res2 = await asyncio.gather(t1, t2)
        assert len(res1) == 1 and len(res2) == 1

        # Once slots drain, resolver cleanly handles fresh lookups.
        res3 = await resolver.resolve(
            "h4.test",
            443,
            timeout=1.0,
            resolver_fn=lambda h, p: [_gai_entry("93.184.216.34")],
        )
        assert res3[0][4][0] == "93.184.216.34"

    try:
        asyncio.run(exercise_saturation())
    finally:
        gate.set()


def test_dns_error_classification_and_delivery_service_retry_vs_permanent(
    db_session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_eai_again(host: str, port: Any, *args: Any, **kwargs: Any):
        raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")

    def raise_eai_noname(host: str, port: Any, *args: Any, **kwargs: Any):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    # 1. Transient DNS failure -> RETRYABLE_FAILURE -> DeliveryStatus.RETRYING
    monkeypatch.setattr(socket, "getaddrinfo", raise_eai_again)
    with pytest.raises(TransientDNSResolutionError):
        asyncio.run(async_resolve_and_pin_target("https://transient.example.test/hook", allow_internal=False))

    ep1 = Endpoint(
        id=str(uuid.uuid4()),
        url="https://transient.example.test/hook",
        secret=generate_signing_secret(),
        is_active=True,
        event_types=["*"],
    )
    ev1 = Event(id=str(uuid.uuid4()), event_type="order.placed", payload={"id": 1})
    del1 = Delivery(
        id=str(uuid.uuid4()),
        event_id=ev1.id,
        endpoint_id=ep1.id,
        status=DeliveryStatus.PENDING,
        max_attempts=5,
    )
    db_session.add_all([ep1, ev1, del1])
    db_session.commit()

    updated1 = DeliveryService.execute_delivery(db_session, del1.id, worker_id="worker-dns-1")
    assert updated1 is not None
    assert updated1.status == DeliveryStatus.RETRYING
    assert updated1.attempt_count == 1
    assert updated1.next_retry_at is not None

    # 2. Permanent DNS failure (NXDOMAIN) -> PERMANENT_FAILURE -> DeliveryStatus.FAILED
    monkeypatch.setattr(socket, "getaddrinfo", raise_eai_noname)
    with pytest.raises(PermanentDNSResolutionError):
        asyncio.run(async_resolve_and_pin_target("https://nxdomain.example.test/hook", allow_internal=False))

    ep2 = Endpoint(
        id=str(uuid.uuid4()),
        url="https://nxdomain.example.test/hook",
        secret=generate_signing_secret(),
        is_active=True,
        event_types=["*"],
    )
    ev2 = Event(id=str(uuid.uuid4()), event_type="order.placed", payload={"id": 2})
    del2 = Delivery(
        id=str(uuid.uuid4()),
        event_id=ev2.id,
        endpoint_id=ep2.id,
        status=DeliveryStatus.PENDING,
        max_attempts=5,
    )
    db_session.add_all([ep2, ev2, del2])
    db_session.commit()

    updated2 = DeliveryService.execute_delivery(db_session, del2.id, worker_id="worker-dns-2")
    assert updated2 is not None
    assert updated2.status == DeliveryStatus.FAILED
    assert updated2.attempt_count == 1
    assert updated2.next_retry_at is None
