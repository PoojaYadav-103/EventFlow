import asyncio
from dataclasses import dataclass
import errno
import ipaddress
import queue
import re
import socket
import threading
import time
from typing import Any, Callable, Iterator, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit, urlunsplit

import httpx
import idna

from app.core.config import settings

MAX_URL_LENGTH = 2048
MAX_HOSTNAME_LENGTH = 253
MAX_LABEL_LENGTH = 63
MAX_CONCURRENT_DNS_LOOKUPS = 16
MAX_PINNED_CONNECT_IPS = 8
DEFAULT_DNS_TIMEOUT_SECONDS = 5.0

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


class PermanentDNSResolutionError(SSRFProtectionError):
    """Raised when hostname resolution fails permanently (e.g., NXDOMAIN/NODATA)."""
    pass


class TransientDNSResolutionError(OSError):
    """Raised when hostname resolution fails due to a transient resolver error (e.g., EAI_AGAIN)."""
    pass


class DNSResolutionTimeoutError(TimeoutError):
    """Raised when DNS resolution exceeds its configured timeout or bounded concurrency budget."""
    pass


@dataclass(frozen=True)
class _PrevalidatedURL:
    normalized_url: str
    scheme: str
    host: str
    port: int
    literal_ip: Optional[IPAddress]
    allow_internal: bool


@dataclass(frozen=True)
class PinnedTarget:
    """Immutable snapshot of a validated destination URL and its pinned canonical IP list."""
    normalized_url: str
    scheme: str
    host: str
    port: int
    pinned_ips: Tuple[str, ...]
    is_ip_literal: bool
    allow_internal: bool


_TRANSIENT_EAI_ERRNOS = frozenset(
    errno
    for name in ("EAI_AGAIN", "EAI_SYSTEM", "EAI_MEMORY")
    if (errno := getattr(socket, name, None)) is not None
)


def _deliver_dns_future(
    fut: asyncio.Future,
    result: Any,
    exc: Optional[BaseException],
) -> None:
    if fut.done():
        return
    if exc is not None:
        fut.set_exception(exc)
    else:
        fut.set_result(result)


class BoundedDNSResolver:
    """
    Bounded daemon-thread DNS executor.

    Using a bounded daemon pool instead of loop's default executor guarantees:
    1. Cancelling a timed-out asyncio task never causes asyncio.run() to block
       up to THREAD_JOIN_TIMEOUT (300s) joining a stuck C getaddrinfo() call.
    2. Stuck OS resolver calls cannot accumulate unbounded threads because active
       concurrency is capped strictly at `max_workers`.
    """

    def __init__(self, max_workers: int = MAX_CONCURRENT_DNS_LOOKUPS) -> None:
        if max_workers <= 0:
            raise ValueError("max_workers must be positive")
        self._max_workers = max_workers
        self._semaphore = threading.BoundedSemaphore(max_workers)
        self._queue: queue.SimpleQueue[
            tuple[asyncio.AbstractEventLoop, asyncio.Future, Callable[..., Any], str, int]
        ] = queue.SimpleQueue()
        self._worker_lock = threading.Lock()
        self._spawned_workers = 0
        self._active_or_queued = 0

    def _worker_loop(self) -> None:
        while True:
            loop, fut, resolver_fn, host, port = self._queue.get()
            result: Any = None
            exc: Optional[BaseException] = None
            try:
                result = resolver_fn(host, port)
            except BaseException as err:
                exc = err
            finally:
                with self._worker_lock:
                    self._active_or_queued -= 1
                self._semaphore.release()

            try:
                if not loop.is_closed():
                    loop.call_soon_threadsafe(_deliver_dns_future, fut, result, exc)
            except RuntimeError:
                pass

    def _ensure_worker_available(self) -> None:
        with self._worker_lock:
            self._active_or_queued += 1
            if self._active_or_queued > self._spawned_workers and self._spawned_workers < self._max_workers:
                self._spawned_workers += 1
                thread = threading.Thread(
                    target=self._worker_loop,
                    name=f"eventflow-dns-{self._spawned_workers}",
                    daemon=True,
                )
                thread.start()

    async def resolve(
        self,
        host: str,
        port: int,
        *,
        timeout: Optional[float] = None,
        resolver_fn: Optional[Callable[..., Any]] = None,
    ) -> Any:
        effective_timeout = DEFAULT_DNS_TIMEOUT_SECONDS if timeout is None else float(timeout)
        if effective_timeout <= 0:
            raise DNSResolutionTimeoutError(f"DNS resolution timed out for '{host}'.")

        deadline = time.monotonic() + effective_timeout
        acquired = self._semaphore.acquire(blocking=False)
        while not acquired:
            remaining_wait = deadline - time.monotonic()
            if remaining_wait <= 0:
                raise DNSResolutionTimeoutError(
                    f"DNS concurrency limit ({self._max_workers}) reached; timed out waiting for resolver slot for '{host}'."
                )
            await asyncio.sleep(min(0.01, remaining_wait))
            acquired = self._semaphore.acquire(blocking=False)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            self._semaphore.release()
            raise DNSResolutionTimeoutError(
                f"DNS resolution timed out after {effective_timeout:.2f}s for '{host}'."
            )

        fn = socket.getaddrinfo if resolver_fn is None else resolver_fn
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        try:
            self._ensure_worker_available()
            self._queue.put((loop, fut, fn, host, port))
        except BaseException:
            with self._worker_lock:
                self._active_or_queued = max(0, self._active_or_queued - 1)
            self._semaphore.release()
            raise

        try:
            return await asyncio.wait_for(fut, timeout=remaining)
        except TimeoutError as exc:
            raise DNSResolutionTimeoutError(
                f"DNS resolution timed out after {effective_timeout:.2f}s for '{host}'."
            ) from exc


_dns_resolver = BoundedDNSResolver(max_workers=MAX_CONCURRENT_DNS_LOOKUPS)


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


_TRANSIENT_OS_ERRNOS = frozenset(
    err
    for name in ("EAGAIN", "EWOULDBLOCK", "ETIMEDOUT", "ENETUNREACH", "EHOSTUNREACH")
    if (err := getattr(errno, name, None)) is not None
)


def _canonicalize_allowed_ip(ip_str: str) -> str:
    ip_obj = ipaddress.ip_address(ip_str)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        return ip_obj.ipv4_mapped.compressed
    return ip_obj.compressed


def _order_pinned_ips(unique_ips: Sequence[str]) -> Tuple[str, ...]:
    """
    Preserve resolution preference while prioritizing fast dual-stack fallback:
    place the first address of the alternate IP family second if present, then
    truncate dialed candidates to MAX_PINNED_CONNECT_IPS.
    """
    if len(unique_ips) <= 1:
        return tuple(unique_ips)

    first_ip = unique_ips[0]
    first_version = ipaddress.ip_address(first_ip).version
    other_idx: Optional[int] = None
    for idx in range(1, len(unique_ips)):
        if ipaddress.ip_address(unique_ips[idx]).version != first_version:
            other_idx = idx
            break

    if other_idx is None or other_idx == 1:
        return tuple(unique_ips[:MAX_PINNED_CONNECT_IPS])

    reordered = [first_ip, unique_ips[other_idx]]
    reordered.extend(unique_ips[idx] for idx in range(1, len(unique_ips)) if idx != other_idx)
    return tuple(reordered[:MAX_PINNED_CONNECT_IPS])


def _validate_and_order_addrinfo(
    host: str,
    addr_info: Any,
    allow_internal: bool,
) -> Tuple[str, ...]:
    """
    Validate every IP returned by DNS against SSRF policy before returning any IP.
    Raises SSRFProtectionError on any disallowed/mixed IP and PermanentDNSResolutionError
    if no usable stream addresses remain.
    """
    if not addr_info:
        raise PermanentDNSResolutionError(f"Could not resolve hostname '{host}'.")

    validated_stream_ips: list[str] = []
    seen: set[str] = set()
    all_raw_ips: list[str] = []

    for info in addr_info:
        if not info or len(info) < 5 or not info[4]:
            continue
        raw_ip = info[4][0]
        all_raw_ips.append(raw_ip)
        if not is_ip_allowed(raw_ip, allow_internal=allow_internal):
            raise SSRFProtectionError(
                f"Destination resolves to forbidden private/internal IP address '{raw_ip}'."
            )

        socktype = info[1] if len(info) > 1 else 0
        if socktype in (0, socket.SOCK_STREAM):
            canon = _canonicalize_allowed_ip(raw_ip)
            if canon not in seen:
                seen.add(canon)
                validated_stream_ips.append(canon)

    if not all_raw_ips or not validated_stream_ips:
        raise PermanentDNSResolutionError(f"Could not resolve hostname '{host}'.")

    return _order_pinned_ips(validated_stream_ips)


def _classify_dns_oserror(host: str, exc: OSError) -> Exception:
    """Distinguish transient resolver failures from permanent NXDOMAIN/name errors."""
    if isinstance(exc, TimeoutError):
        return DNSResolutionTimeoutError(f"DNS resolution timed out for '{host}'.")

    err_no = getattr(exc, "errno", None)
    if isinstance(exc, socket.gaierror):
        if err_no is not None and err_no in _TRANSIENT_EAI_ERRNOS:
            return TransientDNSResolutionError(
                f"Transient DNS resolution failure for '{host}': {exc}"
            )
        return PermanentDNSResolutionError(f"Could not resolve hostname '{host}'.")

    if err_no is not None and err_no in _TRANSIENT_OS_ERRNOS:
        return TransientDNSResolutionError(
            f"Transient DNS resolution failure for '{host}': {exc}"
        )
    return PermanentDNSResolutionError(f"Could not resolve hostname '{host}'.")


def _prevalidate_url(url: str, allow_internal: Optional[bool] = None) -> _PrevalidatedURL:
    """
    Normalize URL and enforce static SSRF constraints without performing DNS lookups.
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

    if not allow_internal:
        if _is_internal_forbidden_hostname(normalized_host):
            raise SSRFProtectionError(
                f"Forbidden host '{normalized_host}'. Localhost and internal hostnames are not permitted."
            )

        if literal_ip is not None and not is_ip_allowed(literal_ip.compressed, allow_internal=False):
            raise SSRFProtectionError(
                f"Destination specifies forbidden private/internal IP address '{literal_ip.compressed}'."
            )

    effective_port = normalized_port if normalized_port is not None else default_port
    return _PrevalidatedURL(
        normalized_url=normalized_url,
        scheme=scheme,
        host=normalized_host,
        port=effective_port,
        literal_ip=literal_ip,
        allow_internal=allow_internal,
    )


def prevalidate_webhook_url_static(url: str, allow_internal: Optional[bool] = None) -> str:
    """Validate URL syntax, normalization, and static SSRF rules without invoking DNS."""
    return _prevalidate_url(url, allow_internal=allow_internal).normalized_url


def validate_webhook_url(url: str, allow_internal: Optional[bool] = None) -> str:
    """
    Validate that a webhook target URL is well-formed, normalized, and safe from SSRF.
    Used for endpoint registration/update. Skips DNS when allow_internal=True so Docker/dev
    hostnames (e.g. backend:8000) can be registered offline, and validates DNS when False.
    """
    pre = _prevalidate_url(url, allow_internal=allow_internal)
    if pre.allow_internal or pre.literal_ip is not None:
        return pre.normalized_url

    try:
        addr_info = socket.getaddrinfo(pre.host, pre.port)
    except OSError as exc:
        raise SSRFProtectionError(f"Could not resolve hostname '{pre.host}'.") from exc

    _validate_and_order_addrinfo(pre.host, addr_info, allow_internal=False)
    return pre.normalized_url


async def async_resolve_and_pin_target(
    url: str,
    allow_internal: Optional[bool] = None,
    dns_timeout: Optional[float] = None,
) -> PinnedTarget:
    """
    Perform a single bounded async DNS lookup and SSRF validation pass immediately before
    connection establishment, returning an immutable PinnedTarget whose validated IP list
    must be dialed directly without a second DNS resolution.
    """
    pre = _prevalidate_url(url, allow_internal=allow_internal)

    if pre.literal_ip is not None:
        if not is_ip_allowed(pre.literal_ip.compressed, allow_internal=pre.allow_internal):
            raise SSRFProtectionError(
                f"Destination specifies forbidden IP address '{pre.literal_ip.compressed}'."
            )
        canon_ip = _canonicalize_allowed_ip(pre.literal_ip.compressed)
        return PinnedTarget(
            normalized_url=pre.normalized_url,
            scheme=pre.scheme,
            host=pre.host,
            port=pre.port,
            pinned_ips=(canon_ip,),
            is_ip_literal=True,
            allow_internal=pre.allow_internal,
        )

    try:
        addr_info = await _dns_resolver.resolve(
            pre.host,
            pre.port,
            timeout=dns_timeout,
            resolver_fn=socket.getaddrinfo,
        )
    except DNSResolutionTimeoutError:
        raise
    except TimeoutError as exc:
        raise DNSResolutionTimeoutError(f"DNS resolution timed out for '{pre.host}'.") from exc
    except OSError as exc:
        raise _classify_dns_oserror(pre.host, exc) from exc

    pinned_ips = _validate_and_order_addrinfo(pre.host, addr_info, allow_internal=pre.allow_internal)
    return PinnedTarget(
        normalized_url=pre.normalized_url,
        scheme=pre.scheme,
        host=pre.host,
        port=pre.port,
        pinned_ips=pinned_ips,
        is_ip_literal=False,
        allow_internal=pre.allow_internal,
    )
