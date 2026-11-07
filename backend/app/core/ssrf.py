import socket
import ipaddress
from urllib.parse import urlparse
from app.core.config import settings


class SSRFProtectionError(ValueError):
    """Raised when a URL violates SSRF safety constraints."""
    pass


FORBIDDEN_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "::1",
    "metadata.google.internal",
    "instance-data",
}


def is_ip_allowed(ip_str: str, allow_internal: bool) -> bool:
    """Check if an IP address is considered safe from SSRF."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if allow_internal:
        return True

    # Disallow private, loopback, link-local, multicast, reserved
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    # Block AWS / GCP / Azure metadata service explicitly
    if ip_str == "169.254.169.254":
        return False

    return True


def validate_webhook_url(url: str, allow_internal: bool = None) -> str:
    """
    Validate that a webhook target URL is well-formed and safe from SSRF.
    Returns the validated URL or raises SSRFProtectionError.
    """
    if allow_internal is None:
        allow_internal = settings.ALLOW_INTERNAL_NETWORKS

    if not url or not isinstance(url, str):
        raise SSRFProtectionError("Webhook URL must be a non-empty string.")

    try:
        parsed = urlparse(url.strip())
    except Exception as e:
        raise SSRFProtectionError(f"Invalid URL structure: {e}")

    if parsed.scheme not in ("http", "https"):
        raise SSRFProtectionError(
            f"Unsupported scheme '{parsed.scheme}'. Only 'http' and 'https' are permitted."
        )

    hostname = parsed.hostname
    if not hostname:
        raise SSRFProtectionError("Webhook URL must contain a valid host.")

    # In local development or automated testing with mock receivers, skip external checks
    if allow_internal:
        return url.strip()

    # Check against known forbidden hostnames
    if hostname.lower() in FORBIDDEN_HOSTNAMES:
        raise SSRFProtectionError(
            f"Forbidden host '{hostname}'. Localhost and internal metadata hosts are not permitted."
        )

    # If hostname is an IP literal, evaluate directly without DNS lookup
    try:
        ipaddress.ip_address(hostname)
        if not is_ip_allowed(hostname, allow_internal=False):
            raise SSRFProtectionError(
                f"Destination specifies forbidden private/internal IP address '{hostname}'."
            )
        return url.strip()
    except ValueError:
        pass  # It is a domain name, proceed with resolution

    # Resolve hostname to IP to protect against DNS rebinding & private IP ranges
    try:
        # getaddrinfo returns family, type, proto, canonname, sockaddr
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        resolved_ips = {info[4][0] for info in addr_info}
    except socket.gaierror:
        # In testing or development, mock hosts might not be resolvable via real DNS
        if allow_internal:
            return url.strip()
        raise SSRFProtectionError(f"Could not resolve hostname '{hostname}'.")

    for resolved_ip in resolved_ips:
        if not is_ip_allowed(resolved_ip, allow_internal=allow_internal):
            raise SSRFProtectionError(
                f"Destination resolves to forbidden private/internal IP address '{resolved_ip}'."
            )

    return url.strip()
