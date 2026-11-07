import pytest
from app.core.ssrf import validate_webhook_url, SSRFProtectionError


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
