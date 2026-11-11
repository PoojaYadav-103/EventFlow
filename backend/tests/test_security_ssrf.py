import http.server
import socket
import threading
from unittest.mock import patch

import httpx
import pytest

from app.core.config import Settings, settings
from app.core.ssrf import (
    MAX_URL_LENGTH,
    SSRFProtectionError,
    is_ip_allowed,
    validate_webhook_url,
)
from app.services.webhook_client import HTTPOutcome, execute_webhook_request


def test_default_allow_internal_networks_is_false(monkeypatch):
    """Fail-closed default: Settings without env override must disable internal networks."""
    monkeypatch.delenv("ALLOW_INTERNAL_NETWORKS", raising=False)
    fresh_settings = Settings(_env_file=None)
    assert fresh_settings.ALLOW_INTERNAL_NETWORKS is False


def test_ssrf_blocks_private_and_metadata_ips():
    """Test that SSRF validator rejects private IPs, loopback, and cloud metadata."""
    # Loopback
    with pytest.raises(SSRFProtectionError):
        validate_webhook_url("http://127.0.0.1:8080/hook", allow_internal=False)

    with pytest.raises(SSRFProtectionError):
        validate_webhook_url("http://localhost:3000/hook", allow_internal=False)

    # AWS / GCP metadata IP
    with pytest.raises(SSRFProtectionError):
        validate_webhook_url("http://169.254.169.254/latest/meta-data", allow_internal=False)

    # Private network RFC 1918
    with pytest.raises(SSRFProtectionError):
        validate_webhook_url("http://192.168.1.1/admin", allow_internal=False)

    with pytest.raises(SSRFProtectionError):
        validate_webhook_url("http://10.0.0.1/internal", allow_internal=False)


def test_ssrf_rejects_non_http_schemes():
    """Test that schemes like file://, ftp://, gopher:// are rejected."""
    with pytest.raises(SSRFProtectionError):
        validate_webhook_url("file:///etc/passwd", allow_internal=False)

    with pytest.raises(SSRFProtectionError):
        validate_webhook_url("ftp://example.com/files", allow_internal=False)

    with pytest.raises(SSRFProtectionError):
        validate_webhook_url("gopher://example.com:70/1", allow_internal=False)


@pytest.mark.parametrize(
    "ip_str",
    [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",        # CGNAT RFC 6598
        "100.100.100.200",   # Alibaba Cloud IMDS
        "127.0.0.1",
        "127.1.2.3",
        "169.254.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.0.1",         # IETF protocol assignments
        "192.0.2.1",         # TEST-NET-1
        "192.88.99.1",       # Deprecated 6to4 relay anycast
        "192.168.1.1",
        "198.18.0.1",        # Benchmarking
        "198.51.100.1",      # TEST-NET-2
        "203.0.113.1",       # TEST-NET-3
        "224.0.0.1",         # Multicast
        "240.0.0.1",         # Reserved
        "255.255.255.255",   # Broadcast
    ],
)
def test_ssrf_blocks_special_and_non_public_ipv4_ranges(ip_str):
    assert is_ip_allowed(ip_str, allow_internal=False) is False
    with pytest.raises(SSRFProtectionError):
        validate_webhook_url(f"http://{ip_str}/hook", allow_internal=False)


@pytest.mark.parametrize(
    "ip_literal",
    [
        "::",
        "::1",
        "::169.254.169.254",      # IPv4-compatible metadata
        "::ffff:127.0.0.1",       # IPv4-mapped loopback
        "::ffff:100.64.0.1",      # IPv4-mapped CGNAT
        "::ffff:169.254.169.254", # IPv4-mapped metadata
        "::ffff:100.100.100.200", # IPv4-mapped Alibaba metadata
        "64:ff9b::127.0.0.1",     # NAT64 loopback
        "64:ff9b::93.184.216.34", # NAT64 well-known prefix
        "64:ff9b:1::1",           # NAT64 local-use
        "100::1",                 # Discard-only
        "2001::1",                # Teredo
        "2001:2::1",              # Benchmarking
        "2001:db8::1",            # Documentation
        "2002:7f00:0001::",       # 6to4 embedding 127.0.0.1
        "fc00::1",                # Unique local
        "fd00:ec2::254",          # AWS IPv6 IMDS
        "fe80::1",                # Link-local
        "fec0::1",                # Deprecated site-local
        "ff02::1",                # Multicast
    ],
)
def test_ssrf_blocks_special_and_transition_ipv6_ranges(ip_literal):
    assert is_ip_allowed(ip_literal, allow_internal=False) is False
    with pytest.raises(SSRFProtectionError):
        validate_webhook_url(f"http://[{ip_literal}]/hook", allow_internal=False)


@pytest.mark.parametrize(
    "scoped_url,scoped_ip",
    [
        ("http://[::1%lo]/hook", "::1%lo"),
        ("http://[fe80::1%eth0]/hook", "fe80::1%eth0"),
        ("http://[fe80::1%25eth0]/hook", "fe80::1%25eth0"),
        ("http://[2001:4860:4860::8888%eth0]/hook", "2001:4860:4860::8888%eth0"),
    ],
)
def test_ssrf_rejects_ipv6_zone_and_scope_ids(scoped_url, scoped_ip):
    assert is_ip_allowed(scoped_ip, allow_internal=False) is False
    assert is_ip_allowed(scoped_ip, allow_internal=True) is False
    with pytest.raises(SSRFProtectionError):
        validate_webhook_url(scoped_url, allow_internal=False)
    with pytest.raises(SSRFProtectionError):
        validate_webhook_url(scoped_url, allow_internal=True)


def test_ssrf_allows_public_unicast_ipv4_and_ipv6():
    assert is_ip_allowed("93.184.216.34", allow_internal=False) is True
    assert is_ip_allowed("2606:2800:220:1:248:1893:25c8:1946", allow_internal=False) is True
    assert is_ip_allowed("::ffff:93.184.216.34", allow_internal=False) is True

    assert (
        validate_webhook_url("https://93.184.216.34/webhooks", allow_internal=False)
        == "https://93.184.216.34/webhooks"
    )
    assert (
        validate_webhook_url("http://[2606:2800:0220:0001:0248:1893:25c8:1946]/hook", allow_internal=False)
        == "http://[2606:2800:220:1:248:1893:25c8:1946]/hook"
    )
    assert (
        validate_webhook_url("https://[::ffff:93.184.216.34]/hook", allow_internal=False)
        == "https://[::ffff:93.184.216.34]/hook"
    )


@pytest.mark.parametrize(
    "alt_url",
    [
        "http://0x7f000001/hook",
        "http://2130706433/hook",
        "http://0177.0.0.1/hook",
        "http://127.1/hook",
        "http://127.0.1/hook",
        "http://0/hook",
        "http://127.0.0.01/hook",
        "http://93.184.216.34./hook",
    ],
)
def test_ssrf_rejects_alternative_ipv4_notations(alt_url):
    with pytest.raises(SSRFProtectionError):
        validate_webhook_url(alt_url, allow_internal=False)
    with pytest.raises(SSRFProtectionError):
        validate_webhook_url(alt_url, allow_internal=True)


@pytest.mark.parametrize(
    "metadata_url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.253/",
        "http://169.254.169.123/",
        "http://169.254.170.2/v2/credentials",
        "http://100.100.100.200/latest/meta-data/",
        "http://[fd00:ec2::254]/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://[::ffff:100.100.100.200]/latest/meta-data/",
        "http://[64:ff9b::169.254.169.254]/latest/meta-data/",
        "http://[2002:a9fe:a9fe::]/latest/meta-data/",
        "http://[::169.254.169.254]/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal./computeMetadata/v1/",
        "http://sub.metadata.google.internal/computeMetadata/v1/",
        "http://metadata.goog/computeMetadata/v1/",
        "http://metadata.azure.com/metadata/instance",
        "http://instance-data/latest/",
        "http://metadata/latest/",
    ],
)
def test_cloud_metadata_always_blocked_even_with_allow_internal(metadata_url):
    with pytest.raises(SSRFProtectionError):
        validate_webhook_url(metadata_url, allow_internal=True)
    with pytest.raises(SSRFProtectionError):
        validate_webhook_url(metadata_url, allow_internal=False)


def test_is_ip_allowed_always_blocks_cloud_metadata_ips():
    for ip in ("169.254.169.254", "100.100.100.200", "fd00:ec2::254", "::ffff:169.254.169.254"):
        assert is_ip_allowed(ip, allow_internal=True) is False
        assert is_ip_allowed(ip, allow_internal=False) is False


def test_allow_internal_preserves_dev_and_mock_receiver_urls():
    for url in (
        "http://backend:8000/api/v1/mock-receiver/webhook",
        "http://localhost:8000/api/v1/mock-receiver/webhook",
        "http://127.0.0.1:8080/hook",
        "https://api.example.com/webhooks/orders",
    ):
        assert validate_webhook_url(url, allow_internal=True) == url


def test_ssrf_port_policy_allows_1_to_65535_and_rejects_invalid_ports():
    # Valid ports 1..65535 allowed (with default 80/443 stripped cleanly)
    assert validate_webhook_url("http://93.184.216.34:1/h", allow_internal=False) == "http://93.184.216.34:1/h"
    assert validate_webhook_url("http://93.184.216.34:22/h", allow_internal=False) == "http://93.184.216.34:22/h"
    assert validate_webhook_url("http://93.184.216.34:65535/h", allow_internal=False) == "http://93.184.216.34:65535/h"
    assert validate_webhook_url("http://93.184.216.34:80/h", allow_internal=False) == "http://93.184.216.34/h"
    assert validate_webhook_url("https://93.184.216.34:443/h", allow_internal=False) == "https://93.184.216.34/h"

    invalid_port_urls = [
        "http://93.184.216.34:0/h",
        "http://93.184.216.34:/h",
        "http://[::1]:/h",
        "http://93.184.216.34:65536/h",
        "http://93.184.216.34:99999/h",
        "http://93.184.216.34:abc/h",
        "http://93.184.216.34:80:80/h",
        "http://93.184.216.34:+80/h",
    ]
    for bad_url in invalid_port_urls:
        with pytest.raises(SSRFProtectionError):
            validate_webhook_url(bad_url, allow_internal=False)
        with pytest.raises(SSRFProtectionError):
            validate_webhook_url(bad_url, allow_internal=True)


@pytest.mark.parametrize(
    "malformed_url",
    [
        "http://user:pass@93.184.216.34/hook",
        "http://user@93.184.216.34/hook",
        "http://@93.184.216.34/hook",
        "http://93.184.216.34\\@127.0.0.1/hook",
        "http://93.184.216.34\\admin",
        "http://93.184.216.34/hook#fragment",
        "http://93.184.216.34/hook\n",
        "http://93.184.216.34/a\nb",
        "http://93.184.216.34/a\rb",
        "http://93.184.216.34/a\tb",
        "http://93.184.216.34/a\x00b",
        "http://93.184.216.34/a b",
        "http://localh\uff4fst/hook",
        "http://127.0.0.1\uff0fadmin",
        "https://93.184.216.34/" + ("a" * MAX_URL_LENGTH),
        "http://",
        "http:///path",
    ],
)
def test_ssrf_rejects_malformed_credentials_fragments_control_chars_and_length(malformed_url):
    with pytest.raises(SSRFProtectionError):
        validate_webhook_url(malformed_url, allow_internal=False)
    with pytest.raises(SSRFProtectionError):
        validate_webhook_url(malformed_url, allow_internal=True)


@pytest.mark.parametrize(
    "forbidden_host_url",
    [
        "http://localhost/hook",
        "http://localhost./hook",
        "http://sub.localhost/hook",
        "http://localhost.localdomain/hook",
        "http://ip6-localhost/hook",
        "http://ip6-loopback/hook",
        "http://printer.local/hook",
        "http://service.internal/hook",
    ],
)
def test_ssrf_rejects_forbidden_local_hostnames(forbidden_host_url):
    with pytest.raises(SSRFProtectionError):
        validate_webhook_url(forbidden_host_url, allow_internal=False)


def test_ssrf_dns_resolution_and_idna_normalization():
    def fake_public_dns(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    with patch("app.core.ssrf.socket.getaddrinfo", side_effect=fake_public_dns):
        assert (
            validate_webhook_url("HTTPS://API.Example.COM:443/WebHooks?x=1", allow_internal=False)
            == "https://api.example.com/WebHooks?x=1"
        )
        assert (
            validate_webhook_url("https://bücher.example./hook", allow_internal=False)
            == "https://xn--bcher-kva.example/hook"
        )
        assert (
            validate_webhook_url("https://01.api.example.com/hook", allow_internal=False)
            == "https://01.api.example.com/hook"
        )

    # Mixed DNS response containing one public and one CGNAT/private IP must be rejected
    def fake_mixed_dns(host, port):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("100.64.0.5", port)),
        ]

    with patch("app.core.ssrf.socket.getaddrinfo", side_effect=fake_mixed_dns):
        with pytest.raises(SSRFProtectionError):
            validate_webhook_url("https://dual.example.com/hook", allow_internal=False)

    # Unresolvable DNS must fail closed when allow_internal=False
    with patch("app.core.ssrf.socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
        with pytest.raises(SSRFProtectionError):
            validate_webhook_url("https://nonexistent.example.com/hook", allow_internal=False)


def _drain_post_body(handler: http.server.BaseHTTPRequestHandler) -> None:
    """Drain incoming POST body bytes so Windows closesocket() does not emit TCP RST."""
    content_length = int(handler.headers.get("Content-Length", "0") or 0)
    if content_length > 0:
        handler.rfile.read(content_length)


def test_webhook_client_does_not_follow_redirects():
    """Verify HTTP 301/302/307/308 redirects are never followed and become PERMANENT_FAILURE."""
    target_hits = []
    redirect_status_holder = {"code": 302}

    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            _drain_post_body(self)
            if self.path == "/secret-target":
                target_hits.append(self.path)
                body = b"should-not-be-reached"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self.send_response(redirect_status_holder["code"])
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/secret-target")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for code in (301, 302, 307, 308):
            redirect_status_holder["code"] = code
            res = execute_webhook_request(
                url=f"http://127.0.0.1:{server.server_port}/redirector",
                secret="whsec_redirect_test",
                event_id="evt_redir",
                delivery_id="del_redir",
                event_type="test.redirect",
                payload={"ok": True},
                allow_internal=True,
            )
            assert res.success is False
            assert res.http_status == code
            assert res.outcome == HTTPOutcome.PERMANENT_FAILURE
            assert target_hits == []
    finally:
        server.shutdown()
        server.server_close()


def test_webhook_client_ignores_env_proxies_trust_env_false(monkeypatch):
    """Verify trust_env=False prevents HTTP_PROXY/HTTPS_PROXY bypasses."""
    class OkHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            _drain_post_body(self)
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), OkHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # Point HTTP_PROXY at an unused port; if trust_env were True this request would fail
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:59998")
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:59998")
        res = execute_webhook_request(
            url=f"http://127.0.0.1:{server.server_port}/ok",
            secret="whsec_proxy_test",
            event_id="evt_proxy",
            delivery_id="del_proxy",
            event_type="test.proxy",
            payload={"ok": True},
            allow_internal=True,
        )
        assert res.success is True
        assert res.http_status == 200
        assert res.outcome == HTTPOutcome.SUCCESS
    finally:
        server.shutdown()
        server.server_close()


def test_webhook_client_handles_invalid_url_without_crashing():
    # Out-of-range port rejected as PERMANENT_FAILURE without crashing
    res1 = execute_webhook_request(
        url="http://93.184.216.34:99999/hook",
        secret="whsec_invalid",
        event_id="evt_inv1",
        delivery_id="del_inv1",
        event_type="test.invalid",
        payload={},
        allow_internal=False,
    )
    assert res1.success is False
    assert res1.outcome == HTTPOutcome.PERMANENT_FAILURE

    # Defensive handling if transport raises httpx.InvalidURL directly
    with patch("app.services.webhook_client.validate_webhook_url", return_value="https://93.184.216.34/hook"):
        with patch("app.services.webhook_client._run_with_overall_deadline", side_effect=httpx.InvalidURL("bad url")):
            res2 = execute_webhook_request(
                url="https://93.184.216.34/hook",
                secret="whsec_invalid",
                event_id="evt_inv2",
                delivery_id="del_inv2",
                event_type="test.invalid",
                payload={},
                allow_internal=False,
            )
    assert res2.success is False
    assert res2.outcome == HTTPOutcome.PERMANENT_FAILURE
    assert "Invalid destination URL" in (res2.error_message or "")


def test_delivery_service_marks_ssrf_blocked_delivery_permanent_failure(client, monkeypatch):
    """If an endpoint URL fails SSRF validation at delivery time, delivery transitions cleanly to FAILED."""
    monkeypatch.setattr(settings, "ALLOW_INTERNAL_NETWORKS", True)
    reg = client.post(
        "/api/v1/endpoints",
        json={"url": "http://127.0.0.1:8080/internal-hook", "event_types": ["order.placed"]},
    )
    assert reg.status_code == 201

    # Flip policy to strict before delivery executes
    monkeypatch.setattr(settings, "ALLOW_INTERNAL_NETWORKS", False)
    ev = client.post(
        "/api/v1/events",
        json={"event_type": "order.placed", "payload": {"id": 1}},
    )
    assert ev.status_code == 201
    event_id = ev.json()["id"]

    from app.workers.tasks import sweep_outbox_task
    processed = sweep_outbox_task()
    assert processed == 1

    delivs = client.get(f"/api/v1/deliveries?event_id={event_id}").json()
    assert len(delivs) == 1
    assert delivs[0]["status"] == "FAILED"
    assert "SSRF Protection blocked request" in (delivs[0]["last_error"] or "")


def test_endpoint_post_and_patch_ssrf_and_normalization_consistency(client, monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_INTERNAL_NETWORKS", False)

    # Seed one valid public IP endpoint to exercise PATCH consistently
    create_ok = client.post(
        "/api/v1/endpoints",
        json={"url": "  HTTPS://93.184.216.34:443/WebHooks?env=prod  ", "event_types": ["*"]},
    )
    assert create_ok.status_code == 201
    created = create_ok.json()
    assert created["url"] == "https://93.184.216.34/WebHooks?env=prod"
    ep_id = created["id"]

    # PATCH normalizes updated URL too
    patch_ok = client.patch(
        f"/api/v1/endpoints/{ep_id}",
        json={"url": "HTTP://93.184.216.34:8080/Updated"},
    )
    assert patch_ok.status_code == 200
    assert patch_ok.json()["url"] == "http://93.184.216.34:8080/Updated"

    # SSRF violations must return HTTP 400 on both POST and PATCH
    ssrf_urls = [
        "http://127.0.0.1/hook",
        "http://100.64.0.1/hook",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/hook",
        "http://[fec0::1]/hook",
        "http://0x7f000001/hook",
        "http://93.184.216.34:0/hook",
        "http://93.184.216.34:99999/hook",
        "http://93.184.216.34:/hook",
        "http://user:pass@93.184.216.34/hook",
        "http://93.184.216.34/hook#frag",
        "http://93.184.216.34/hook\n",
    ]
    for bad_url in ssrf_urls:
        post_resp = client.post("/api/v1/endpoints", json={"url": bad_url})
        patch_resp = client.patch(f"/api/v1/endpoints/{ep_id}", json={"url": bad_url})
        assert post_resp.status_code == 400, f"POST unexpected {post_resp.status_code} for {bad_url!r}"
        assert patch_resp.status_code == 400, f"PATCH unexpected {patch_resp.status_code} for {bad_url!r}"

    # Schema violations must return HTTP 422 on both POST and PATCH
    schema_bad_urls = [
        "ftp://93.184.216.34/files",
        "",
        "https://93.184.216.34/" + ("x" * MAX_URL_LENGTH),
    ]
    for bad_url in schema_bad_urls:
        post_resp = client.post("/api/v1/endpoints", json={"url": bad_url})
        patch_resp = client.patch(f"/api/v1/endpoints/{ep_id}", json={"url": bad_url})
        assert post_resp.status_code == 422, f"POST schema unexpected {post_resp.status_code} for {bad_url!r}"
        assert patch_resp.status_code == 422, f"PATCH schema unexpected {patch_resp.status_code} for {bad_url!r}"

    # When ALLOW_INTERNAL_NETWORKS=True, Docker/localhost presets work while metadata remains HTTP 400
    monkeypatch.setattr(settings, "ALLOW_INTERNAL_NETWORKS", True)
    mock_post = client.post(
        "/api/v1/endpoints",
        json={"url": "http://backend:8000/api/v1/mock-receiver/webhook"},
    )
    assert mock_post.status_code == 201
    meta_post = client.post(
        "/api/v1/endpoints",
        json={"url": "http://169.254.169.254/latest/meta-data/"},
    )
    meta_patch = client.patch(
        f"/api/v1/endpoints/{ep_id}",
        json={"url": "http://metadata.google.internal/computeMetadata/v1/"},
    )
    assert meta_post.status_code == 400
    assert meta_patch.status_code == 400
