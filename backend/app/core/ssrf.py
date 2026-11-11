import ipaddress
import re
import socket
from typing import Iterator, Optional, Union
from urllib.parse import urlsplit, urlunsplit

import httpx
import idna

from app.core.config import settings

MAX_URL_LENGTH = 2048
MAX_HOSTNAME_LENGTH = 253
MAX_LABEL_LENGTH = 63

ASCII_DIGITS = frozenset("0123456789")
HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# Cloud metadata hostnames — blocked unconditionally even when allow_internal=True
CLOUD_METADATA_HOSTNAMES = frozenset({
    "metadata.google.internal",
    "metadata.goog",
    "metadata.azure.com",
    "instance-data",
    "metadata",
})

CLOUD_METADATA_HOSTNAME_SUFFIXES = (
    ".metadata.google.internal",
    ".metadata.goog",
    ".metadata.azure.com",
    ".instance-data",
)

# Cloud metadata IP ranges — blocked unconditionally even when allow_internal=True
CLOUD_METADATA_NETWORKS = (
    ipaddress.ip_network("169.254.169.254/32"),  # AWS / GCP / Azure / DO / Oracle IMDS
    ipaddress.ip_network("169.254.169.253/32"),  # AWS Route 53 Resolver / DNS
    ipaddress.ip_network("169.254.169.123/32"),  # AWS Time Sync
    ipaddress.ip_network("169.254.170.2/32"),    # AWS ECS Task Metadata
    ipaddress.ip_network("169.254.169.250/32"),  # Cloud metadata variant
    ipaddress.ip_network("169.254.169.251/32"),  # Cloud metadata variant
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba Cloud IMDS
    ipaddress.ip_network("fd00:ec2::254/128"),   # AWS IPv6 IMDS
)

# Hostnames reserved for loopback / local / internal resolution (blocked when allow_internal=False)
INTERNAL_FORBIDDEN_HOSTNAMES = frozenset({
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
})

INTERNAL_FORBIDDEN_SUFFIXES = (
    ".localhost",
    ".localhost.localdomain",
    ".local",
    ".internal",
)

# Backward-compatible export of known forbidden hostname literals
FORBIDDEN_HOSTNAMES = CLOUD_METADATA_HOSTNAMES | INTERNAL_FORBIDDEN_HOSTNAMES | {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "::",
    "169.254.169.254",
    "100.100.100.200",
    "fd00:ec2::254",
}

_NAT64_WELL_KNOWN_NET = ipaddress.ip_network("64:ff9b::/96")
_IPV4_COMPAT_NET = ipaddress.ip_network("::/96")

# Explicit special-use / non-public CIDRs (supplements Python ipaddress flags across Python versions)
NON_PUBLIC_NETWORKS = (
    # IPv4 special-use & non-globally-routable ranges
    ipaddress.ip_network("0.0.0.0/8"),          # "This host on this network" (RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),         # Private-Use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # CGNAT / Shared Address Space (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),      # Private-Use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),       # Documentation TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.88.99.0/24"),     # Deprecated 6to4 Relay Anycast (RFC 7526)
    ipaddress.ip_network("192.168.0.0/16"),     # Private-Use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for Future Use & Broadcast (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast
    # IPv6 special-use, tunneling, & non-globally-routable ranges
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/96"),              # Deprecated IPv4-compatible IPv6
    ipaddress.ip_network("64:ff9b::/96"),       # NAT64 Well-Known Prefix (RFC 6052)
    ipaddress.ip_network("64:ff9b:1::/48"),     # NAT64 Local-Use Prefix (RFC 8215)
    ipaddress.ip_network("100::/64"),           # Discard-Only (RFC 6666)
    ipaddress.ip_network("2001::/32"),          # Teredo Tunneling (RFC 4380)
    ipaddress.ip_network("2001:2::/48"),        # Benchmarking (RFC 5180)
    ipaddress.ip_network("2001:db8::/32"),      # Documentation (RFC 3849)
    ipaddress.ip_network("2002::/16"),          # 6to4 Tunneling (RFC 3056)
    ipaddress.ip_network("fc00::/7"),           # Unique Local Addresses (RFC 4193)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast (RFC 4291)
    ipaddress.ip_network("fec0::/10"),          # Deprecated Site-Local (RFC 3879)
    ipaddress.ip_network("ff00::/8"),           # Multicast (RFC 4291)
)


class SSRFProtectionError(ValueError):
    """Raised when a URL violates SSRF safety constraints."""
    pass


def _extract_embedded_ips(ip_obj: IPAddress) -> Iterator[IPAddress]:
    """Yield any IPv4 addresses embedded within IPv6 transition/mapped encodings."""
    if not isinstance(ip_obj, ipaddress.IPv6Address):
        return

    if ip_obj.ipv4_mapped is not None:
        yield ip_obj.ipv4_mapped

    if ip_obj.sixtofour is not None:
        yield ip_obj.sixtofour

    if ip_obj.teredo is not None:
        server_ip, client_ip = ip_obj.teredo
        yield server_ip
        yield client_ip

    if ip_obj in _NAT64_WELL_KNOWN_NET:
        yield ipaddress.IPv4Address(int(ip_obj) & 0xFFFFFFFF)

    if (
        ip_obj in _IPV4_COMPAT_NET
        and ip_obj != ipaddress.IPv6Address("::")
        and ip_obj != ipaddress.IPv6Address("::1")
    ):
        yield ipaddress.IPv4Address(int(ip_obj) & 0xFFFFFFFF)


def _contains_cloud_metadata_ip(ip_obj: IPAddress) -> bool:
    """Return True if ip_obj or any embedded IPv4 targets a cloud metadata service."""
    if any(ip_obj in net for net in CLOUD_METADATA_NETWORKS):
        return True
    return any(_contains_cloud_metadata_ip(sub_ip) for sub_ip in _extract_embedded_ips(ip_obj))


def _is_public_unicast_ip(ip_obj: IPAddress) -> bool:
    """Return True only if ip_obj (and any embedded IPv4) is globally routable unicast."""
    if getattr(ip_obj, "scope_id", None) is not None:
        return False

    if _contains_cloud_metadata_ip(ip_obj):
        return False

    # Delegate IPv4-mapped IPv6 (::ffff:0:0/96) directly to the unwrapped IPv4 check
    # so behavior is identical across Python versions while blocking private/CGNAT mapped IPs.
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        return _is_public_unicast_ip(ip_obj.ipv4_mapped)

    if any(ip_obj in net for net in NON_PUBLIC_NETWORKS):
        return False

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or getattr(ip_obj, "is_site_local", False)
        or not ip_obj.is_global
    ):
        return False

    for sub_ip in _extract_embedded_ips(ip_obj):
        if not _is_public_unicast_ip(sub_ip):
            return False

    return True


def _is_cloud_metadata_hostname(hostname: str) -> bool:
    """Check whether normalized lowercase hostname refers to a cloud metadata host."""
    host = hostname.rstrip(".").lower()
    if host in CLOUD_METADATA_HOSTNAMES:
        return True
    return host.endswith(CLOUD_METADATA_HOSTNAME_SUFFIXES)


def _is_internal_forbidden_hostname(hostname: str) -> bool:
    """Check whether normalized lowercase hostname targets localhost or local-only domains."""
    host = hostname.rstrip(".").lower()
    if host in INTERNAL_FORBIDDEN_HOSTNAMES:
        return True
    return host.endswith(INTERNAL_FORBIDDEN_SUFFIXES)


def _is_numeric_ipv4_part(part: str) -> bool:
    if not part:
        return False
    if part.lower().startswith("0x"):
        return len(part) > 2 and all(c in HEX_CHARS for c in part[2:])
    return all(c in ASCII_DIGITS for c in part)


def _is_noncanonical_ipv4_notation(raw_host: str) -> bool:
    """
    Detect non-canonical/alternative IPv4 notations (decimal integer, hex, octal,
    short-form dotted IPv4 like '127.1', or trailing-dot numeric IPs) that OS resolvers
    such as glibc getaddrinfo/inet_aton interpret ambiguously.
    """
    if ":" in raw_host:
        return False

    has_trailing_dot = raw_host.endswith(".")
    bare = raw_host[:-1] if has_trailing_dot else raw_host
    if not bare:
        return False

    parts = bare.split(".")
    if not (1 <= len(parts) <= 4):
        return False

    if not all(_is_numeric_ipv4_part(p) for p in parts):
        return False

    # Any single/2/3-part numeric host or trailing-dot IP literal is non-canonical
    if has_trailing_dot or len(parts) != 4:
        return True

    # 4 numeric parts: valid ONLY if strict canonical dotted decimal (no hex, no leading zeros)
    try:
        ipaddress.IPv4Address(bare)
        return False
    except ValueError:
        return True


def is_ip_allowed(ip_str: str, allow_internal: bool) -> bool:
    """
    Check if an IP address is permitted by SSRF policy.
    Cloud metadata IPs and scoped IPv6 zone IDs are always rejected, even when allow_internal=True.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False

    # Reject IPv6 zone/scope IDs explicitly
    if "%" in ip_str:
        return False

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if getattr(ip, "scope_id", None) is not None:
        return False

    # Always block cloud metadata IPs even in internal/dev mode
    if _contains_cloud_metadata_ip(ip):
        return False

    if allow_internal:
        return True

    return _is_public_unicast_ip(ip)


def _parse_authority(netloc: str, scheme: str) -> tuple[str, bool, Optional[int]]:
    """
    Strictly parse authority into (raw_host, is_bracketed_ipv6, port).
    Rejects credentials, backslashes, zone IDs, empty ports, port 0, and malformed ports.
    """
    if not netloc:
        raise SSRFProtectionError("Webhook URL must contain a valid host.")

    if "\\" in netloc:
        raise SSRFProtectionError("Webhook URL authority must not contain backslashes.")

    if "@" in netloc:
        raise SSRFProtectionError("Webhook URL must not contain embedded credentials.")

    port: Optional[int] = None
    is_bracketed_ipv6 = False

    if netloc.startswith("["):
        close_idx = netloc.find("]")
        if close_idx == -1:
            raise SSRFProtectionError("Malformed IPv6 host brackets in webhook URL.")
        raw_host = netloc[1:close_idx]
        remainder = netloc[close_idx + 1:]
        if not raw_host:
            raise SSRFProtectionError("Webhook URL must contain a non-empty IPv6 host.")
        if "%" in raw_host:
            raise SSRFProtectionError("IPv6 zone/scope IDs are not permitted in webhook URLs.")
        if remainder:
            if not remainder.startswith(":"):
                raise SSRFProtectionError("Malformed authority following IPv6 host.")
            port_str = remainder[1:]
            if not port_str or not all(c in ASCII_DIGITS for c in port_str):
                raise SSRFProtectionError("Invalid or empty port in webhook URL.")
            port = int(port_str)
        is_bracketed_ipv6 = True
    else:
        if "]" in netloc or "[" in netloc:
            raise SSRFProtectionError("Malformed host brackets in webhook URL.")
        colon_count = netloc.count(":")
        if colon_count > 1:
            raise SSRFProtectionError(
                "Malformed authority in webhook URL (IPv6 literals must use brackets)."
            )
        if colon_count == 1:
            raw_host, port_str = netloc.split(":", 1)
            if not port_str or not all(c in ASCII_DIGITS for c in port_str):
                raise SSRFProtectionError("Invalid or empty port in webhook URL.")
            port = int(port_str)
        else:
            raw_host = netloc

    if not raw_host:
        raise SSRFProtectionError("Webhook URL must contain a valid host.")

    if "%" in raw_host:
        raise SSRFProtectionError("Hostnames must not contain percent-encoding or zone IDs.")

    if port is not None and not (1 <= port <= 65535):
        raise SSRFProtectionError(f"Port {port} is out of valid range (1-65535).")

    # Normalize redundant default ports (80 for http, 443 for https)
    default_port = 443 if scheme == "https" else 80
    normalized_port = None if port == default_port else port

    return raw_host, is_bracketed_ipv6, normalized_port


def _normalize_host_and_ip(raw_host: str, is_bracketed_ipv6: bool) -> tuple[str, Optional[IPAddress]]:
    """
    Validate and normalize host (IDNA Punycode for domains, canonical IP for literals).
    Rejects alternative IPv4 notations and malformed DNS labels.
    """
    if is_bracketed_ipv6:
        try:
            ip_obj = ipaddress.IPv6Address(raw_host)
        except ValueError:
            raise SSRFProtectionError(f"Invalid IPv6 address literal '{raw_host}'.")
        if getattr(ip_obj, "scope_id", None) is not None:
            raise SSRFProtectionError("IPv6 zone/scope IDs are not permitted in webhook URLs.")
        return ip_obj.compressed, ip_obj

    if _is_noncanonical_ipv4_notation(raw_host):
        raise SSRFProtectionError(
            f"Non-canonical or alternative IPv4 host notation '{raw_host}' is not permitted."
        )

    # Check canonical dotted-quad IPv4 literal
    try:
        ip_obj = ipaddress.IPv4Address(raw_host)
        return str(ip_obj), ip_obj
    except ValueError:
        pass

    # Treat as DNS hostname; strip a single trailing root dot
    host_candidate = raw_host[:-1] if raw_host.endswith(".") else raw_host
    if not host_candidate or host_candidate.startswith(".") or ".." in host_candidate:
        raise SSRFProtectionError(f"Invalid hostname '{raw_host}' in webhook URL.")

    try:
        ascii_host = idna.encode(host_candidate.lower(), uts46=False).decode("ascii").lower()
    except idna.IDNAError as e:
        raise SSRFProtectionError(f"Invalid IDNA hostname '{raw_host}': {e}")

    if not ascii_host or len(ascii_host) > MAX_HOSTNAME_LENGTH:
        raise SSRFProtectionError("Webhook hostname exceeds maximum length of 253 characters.")

    labels = ascii_host.split(".")
    for label in labels:
        if len(label) > MAX_LABEL_LENGTH or not _DNS_LABEL_RE.match(label):
            raise SSRFProtectionError(f"Invalid hostname label '{label}' in webhook URL.")

    return ascii_host, None


def validate_webhook_url(url: str, allow_internal: Optional[bool] = None) -> str:
    """
    Validate that a webhook target URL is well-formed, normalized, and safe from SSRF.
    Returns the normalized URL or raises SSRFProtectionError.
    """
    if allow_internal is None:
        allow_internal = settings.ALLOW_INTERNAL_NETWORKS
    allow_internal = bool(allow_internal)

    if not url or not isinstance(url, str):
        raise SSRFProtectionError("Webhook URL must be a non-empty string.")

    # Reject control characters (including \r, \n, \t, \x00) anywhere in raw input before trimming spaces
    for ch in url:
        if ord(ch) < 0x20 or ord(ch) == 0x7F or (ch.isspace() and ch != " "):
            raise SSRFProtectionError("Webhook URL must not contain control or whitespace characters.")

    cleaned_url = url.strip(" ")
    if not cleaned_url:
        raise SSRFProtectionError("Webhook URL must be a non-empty string.")

    if len(cleaned_url) > MAX_URL_LENGTH:
        raise SSRFProtectionError(f"Webhook URL exceeds maximum length of {MAX_URL_LENGTH} characters.")

    # Reject internal spaces anywhere inside the trimmed URL
    if any(ch.isspace() for ch in cleaned_url):
        raise SSRFProtectionError("Webhook URL must not contain whitespace.")

    if "#" in cleaned_url:
        raise SSRFProtectionError("Webhook URL must not contain fragments ('#').")

    try:
        parsed = urlsplit(cleaned_url)
    except ValueError as e:
        raise SSRFProtectionError(f"Invalid URL structure: {e}")

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise SSRFProtectionError(
            f"Unsupported scheme '{parsed.scheme}'. Only 'http' and 'https' are permitted."
        )

    if parsed.fragment:
        raise SSRFProtectionError("Webhook URL must not contain fragments ('#').")

    # Cross-check parsed.port safely so ValueError never escapes un-wrapped
    try:
        raw_split_port = parsed.port
    except ValueError as e:
        raise SSRFProtectionError(f"Invalid port in webhook URL: {e}")

    raw_host, is_bracketed_ipv6, normalized_port = _parse_authority(parsed.netloc, scheme)
    if raw_split_port is not None and not (1 <= raw_split_port <= 65535):
        raise SSRFProtectionError(f"Port {raw_split_port} is out of valid range (1-65535).")

    normalized_host, literal_ip = _normalize_host_and_ip(raw_host, is_bracketed_ipv6)

    netloc_host = f"[{normalized_host}]" if is_bracketed_ipv6 else normalized_host
    normalized_netloc = f"{netloc_host}:{normalized_port}" if normalized_port is not None else netloc_host
    normalized_url = urlunsplit((scheme, normalized_netloc, parsed.path, parsed.query, ""))

    if len(normalized_url) > MAX_URL_LENGTH:
        raise SSRFProtectionError(f"Normalized webhook URL exceeds maximum length of {MAX_URL_LENGTH} characters.")

    # Dual-parser consistency check against httpx.URL (the actual transport parser)
    try:
        httpx_url = httpx.URL(normalized_url)
        httpx_raw_host = httpx_url.raw_host.decode("ascii").lower()
    except (httpx.InvalidURL, UnicodeDecodeError, ValueError) as e:
        raise SSRFProtectionError(f"Webhook URL failed transport parser validation: {e}")

    default_port = 443 if scheme == "https" else 80
    expected_httpx_port = None if normalized_port is None else normalized_port
    if httpx_url.scheme != scheme or httpx_url.port != expected_httpx_port:
        raise SSRFProtectionError("Webhook URL failed parser consistency validation.")

    if literal_ip is not None:
        try:
            if ipaddress.ip_address(httpx_raw_host) != literal_ip:
                raise SSRFProtectionError("Webhook IP host failed parser consistency validation.")
        except ValueError as e:
            raise SSRFProtectionError(f"Webhook IP host failed parser consistency validation: {e}")
    elif httpx_raw_host != normalized_host:
        raise SSRFProtectionError("Webhook hostname failed parser consistency validation.")

    # Block cloud metadata hostnames and IPs unconditionally (even when allow_internal=True)
    if _is_cloud_metadata_hostname(normalized_host):
        raise SSRFProtectionError(
            f"Forbidden cloud metadata host '{normalized_host}' is not permitted."
        )

    if literal_ip is not None and _contains_cloud_metadata_ip(literal_ip):
        raise SSRFProtectionError(
            f"Destination specifies forbidden cloud metadata IP address '{literal_ip}'."
        )

    if allow_internal:
        return normalized_url

    if _is_internal_forbidden_hostname(normalized_host):
        raise SSRFProtectionError(
            f"Forbidden host '{normalized_host}'. Localhost and internal hostnames are not permitted."
        )

    if literal_ip is not None:
        if not is_ip_allowed(literal_ip.compressed, allow_internal=False):
            raise SSRFProtectionError(
                f"Destination specifies forbidden private/internal IP address '{literal_ip.compressed}'."
            )
        return normalized_url

    effective_port = normalized_port if normalized_port is not None else default_port
    try:
        addr_info = socket.getaddrinfo(normalized_host, effective_port)
        resolved_ips = {info[4][0] for info in addr_info if info and len(info) > 4 and info[4]}
    except OSError:
        raise SSRFProtectionError(f"Could not resolve hostname '{normalized_host}'.")

    if not resolved_ips:
        raise SSRFProtectionError(f"Could not resolve hostname '{normalized_host}'.")

    for resolved_ip in resolved_ips:
        if not is_ip_allowed(resolved_ip, allow_internal=False):
            raise SSRFProtectionError(
                f"Destination resolves to forbidden private/internal IP address '{resolved_ip}'."
            )

    return normalized_url
