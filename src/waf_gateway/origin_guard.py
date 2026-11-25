"""
Runtime DNS-Rebinding & Origin SSRF Guard.

Validates upstream origin URLs before opening outbound HTTP connections,
resolving hostnames to IP addresses with a short TTL cache and rejecting
forbidden IP ranges (cloud metadata, link-local, unspecified, multicast,
and optionally private/loopback RFC1918 ranges).
"""
import ipaddress
import socket
import time
from typing import Dict, List, Tuple
from urllib.parse import urlparse


class OriginSSRFBlockedError(ValueError):
    """Raised when an upstream origin resolves to a forbidden or unsafe IP address."""
    pass


# Global in-memory DNS resolution cache with short TTL to defend against DNS rebinding
# format: {hostname: (timestamp, [resolved_ips])}
_DNS_CACHE: Dict[str, Tuple[float, List[str]]] = {}
DNS_CACHE_TTL_SECONDS = 20.0

# Always forbidden ranges regardless of allow_private_origins
ALWAYS_FORBIDDEN_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),     # IPv4 Link-local / AWS / GCP / Azure metadata
    ipaddress.ip_network("fe80::/10"),           # IPv6 Link-local
    ipaddress.ip_network("0.0.0.0/8"),           # IPv4 Current network / unspecified
    ipaddress.ip_network("224.0.0.0/4"),         # IPv4 Multicast
    ipaddress.ip_network("ff00::/8"),            # IPv6 Multicast
]

# Additional metadata IPs
ADDITIONAL_FORBIDDEN_IPS = {
    ipaddress.ip_address("100.100.100.200"),    # Alibaba Cloud metadata
}

# Private & Loopback ranges blocked when allow_private_origins is False
PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),         # IPv4 Loopback
    ipaddress.ip_network("::1/128"),             # IPv6 Loopback
    ipaddress.ip_network("10.0.0.0/8"),          # RFC 1918 Private
    ipaddress.ip_network("172.16.0.0/12"),       # RFC 1918 Private
    ipaddress.ip_network("192.168.0.0/16"),      # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),       # Carrier-Grade NAT
    ipaddress.ip_network("fc00::/7"),            # IPv6 Unique Local Address (ULA)
]


def resolve_hostname(hostname: str) -> List[str]:
    """
    Resolves hostname to IP addresses with a short TTL cache.
    """
    now = time.time()
    cached = _DNS_CACHE.get(hostname)
    if cached is not None:
        ts, ips = cached
        if now - ts < DNS_CACHE_TTL_SECONDS:
            return ips

    try:
        addrinfo = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        ips = list(set([item[4][0] for item in addrinfo]))
    except socket.gaierror as e:
        raise OriginSSRFBlockedError(f"DNS resolution failed for origin host '{hostname}': {e}")
    except Exception as e:
        raise OriginSSRFBlockedError(f"Error resolving origin host '{hostname}': {e}")

    if not ips:
        raise OriginSSRFBlockedError(f"No IP addresses resolved for origin host '{hostname}'")

    _DNS_CACHE[hostname] = (now, ips)
    return ips


def clear_dns_cache() -> None:
    """Clears the runtime DNS resolution cache (useful for testing)."""
    _DNS_CACHE.clear()


def validate_origin_before_connect(
    origin_url: str,
    allow_private_origins: bool = False,
) -> List[str]:
    """
    Validates an origin URL before initiating an outbound HTTP connection.

    1. Parses scheme (must be http or https).
    2. Resolves host via DNS.
    3. Blocks link-local, cloud metadata, unspecified, and multicast IPs ALWAYS.
    4. Blocks loopback and RFC1918 private IPs unless allow_private_origins=True.

    Returns the list of validated IP strings on success.
    Raises OriginSSRFBlockedError on any violation.
    """
    if not origin_url or not isinstance(origin_url, str):
        raise OriginSSRFBlockedError("Origin URL cannot be empty")

    parsed = urlparse(origin_url)
    if parsed.scheme not in ("http", "https"):
        raise OriginSSRFBlockedError(f"Invalid origin scheme '{parsed.scheme}'. Only http and https allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise OriginSSRFBlockedError(f"Missing hostname in origin URL: {origin_url}")

    hostname = hostname.strip().lower()

    # Reject cloud metadata hostnames directly
    if hostname in ("metadata.google.internal", "metadata", "instance-data"):
        raise OriginSSRFBlockedError(f"Forbidden cloud metadata hostname: {hostname}")

    # Check if hostname is already a raw IP literal or needs DNS resolution
    try:
        raw_ip = ipaddress.ip_address(hostname)
        ips = [str(raw_ip)]
    except ValueError:
        ips = resolve_hostname(hostname)

    for ip_str in ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise OriginSSRFBlockedError(f"Invalid resolved IP address '{ip_str}' for origin '{hostname}'")

        # 1. ALWAYS forbidden (metadata, link-local, unspecified, multicast)
        if ip_obj in ADDITIONAL_FORBIDDEN_IPS:
            raise OriginSSRFBlockedError(f"Origin resolved to forbidden cloud metadata IP: {ip_str}")

        if ip_obj.is_unspecified:
            raise OriginSSRFBlockedError(f"Origin resolved to unspecified IP: {ip_str}")

        if ip_obj.is_multicast:
            raise OriginSSRFBlockedError(f"Origin resolved to multicast IP: {ip_str}")

        for net in ALWAYS_FORBIDDEN_NETWORKS:
            if ip_obj in net:
                raise OriginSSRFBlockedError(f"Origin resolved to forbidden link-local or metadata network ({net}): {ip_str}")

        # 2. Private & loopback (only blocked when allow_private_origins=False)
        if not allow_private_origins:
            if ip_obj.is_loopback:
                raise OriginSSRFBlockedError(f"Origin resolved to loopback IP ({ip_str}) while private origins are disabled")

            if ip_obj.is_private:
                raise OriginSSRFBlockedError(f"Origin resolved to private RFC1918/ULA network ({ip_str}) while private origins are disabled")

            for net in PRIVATE_NETWORKS:
                if ip_obj in net:
                    raise OriginSSRFBlockedError(f"Origin resolved to private network ({net}): {ip_str}")

    return ips
