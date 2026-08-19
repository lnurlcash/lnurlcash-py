"""Resolving user input to a URL, and deciding which URLs may be fetched."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from . import bech32

# these hosts (plus .onion) resolve to http:// rather than https://
_INSECURE_HOSTS = {"127.0.0.1", "0.0.0.0", "localhost"}

_LUD17_SCHEMES = ("lnurlw", "lnurlp", "lnurlc", "keyauth")
_LUD17_RE = re.compile(r"^(?:lnurlw|lnurlp|lnurlc|keyauth)://([^/]+)", re.I)
_LIGHTNING_ADDRESS_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_BARE_DOMAIN_RE = re.compile(r"^@?[^\s@/]+\.[^\s@/]+$")
_LNURLP_PATH_RE = re.compile(r"^(.*/\.well-known/)lnurlp/([^/]+)$")


def _is_insecure_host(host: str) -> bool:
    return host in _INSECURE_HOSTS or host.endswith(".onion")


def is_bech32_lnurl(data: str) -> bool:
    return data.strip().upper().startswith("LNURL1")


def to_bech32_lnurl(url: str) -> str:
    return bech32.encode("lnurl", url.encode()).upper()


def from_bech32_lnurl(data: str) -> str | None:
    safe = data.strip()
    if not safe.upper().startswith("LNURL1"):
        return None
    decoded = bech32.decode(safe.lower())
    if decoded is None or decoded[0] != "lnurl":
        return None
    try:
        return decoded[1].decode()
    except UnicodeDecodeError:
        return None


def is_allowed_service_url(value: str) -> bool:
    """The one admission rule every URL must pass, whether it came from a
    scanned or pasted note or from a SERVICE's own response (callback,
    verify, payLink): https anywhere, http only for loopback and .onion.

    Anything else - data:, file:, a bare http:// clearnet host - is rejected,
    so a crafted note cannot answer its own informational GET (a data: URL
    carrying withdrawRequest JSON would otherwise mint a self-contained fake
    note), and a SERVICE cannot redirect a k1-bearing callback onto cleartext.
    """
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    if not parsed.scheme or not parsed.netloc:
        return False
    if parsed.scheme == "https":
        return True
    if parsed.scheme == "http":
        return _is_insecure_host((parsed.hostname or "").lower())
    return False


def from_lud17(url: str) -> str:
    match = _LUD17_RE.match(url)
    if not match:
        return url
    host = match.group(1).split(":")[0]
    scheme = "http" if _is_insecure_host(host) else "https"
    return re.sub(r"^[a-z]+://", f"{scheme}://", url, count=1, flags=re.I)


def to_lud17w(url: str) -> str:
    return re.sub(r"^https?://", "lnurlw://", url, count=1)


def is_lightning_address(value: str) -> bool:
    """LUD-16. Strict: a host with no dot is not a domain name."""
    return bool(_LIGHTNING_ADDRESS_RE.match(value.strip()))


def _is_loopback_lightning_address(value: str) -> bool:
    """A local dev address, "mint@localhost:8000". LUD-16 has no notion of it,
    but pointing a wallet at a mint running on this machine is an ordinary
    thing to want, and the resolution below already handles the port and the
    cleartext scheme such a host needs."""
    parts = value.strip().split("@")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return False
    return _is_insecure_host(parts[1].split(":")[0])


def _ln_address_to_url(address: str) -> str:
    name, domain = address.strip().split("@")
    # the domain may carry a port (mint@127.0.0.1:8000) - the insecure-host
    # check is about the host part only
    scheme = "http" if _is_insecure_host(domain.split(":")[0]) else "https"
    return f"{scheme}://{domain}/.well-known/lnurlp/{name}"


def _is_bare_mint_domain(value: str) -> bool:
    """A bare mint domain with no local part. Assumes the "mint" username that
    lnurl-mint itself defaults to, so a mint using a different one simply
    fails to resolve and must be typed out in full."""
    trimmed = value.strip()
    if is_lightning_address(trimmed):
        return False
    if _BARE_DOMAIN_RE.match(trimmed):
        return True
    return _is_insecure_host(trimmed.lstrip("@").split(":")[0])


def resolve_mint_input(value: str) -> str | None:
    """A bech32 LNURL, a Lightning Address, or a bare mint domain - all of
    which point unambiguously at one payRequest."""
    trimmed = value.strip()
    if not trimmed:
        return None
    if is_bech32_lnurl(trimmed):
        url = from_bech32_lnurl(trimmed)
        return url if url and is_allowed_service_url(url) else None
    if is_lightning_address(trimmed) or _is_loopback_lightning_address(trimmed):
        return _ln_address_to_url(trimmed)
    if _is_bare_mint_domain(trimmed):
        return _ln_address_to_url(f"mint@{trimmed.lstrip('@')}")
    return None


def resolve_lnurl_input(value: str) -> str | None:
    """Arbitrary LNURL-ish input down to a fetchable URL. Every URL-producing
    branch passes is_allowed_service_url, so a decoded or pasted URL can never
    smuggle in a non-https scheme or cleartext http to a clearnet host."""
    trimmed = value.strip()
    if not trimmed:
        return None
    if is_bech32_lnurl(trimmed):
        url = from_bech32_lnurl(trimmed)
        return url if url and is_allowed_service_url(url) else None
    if trimmed.lower().startswith(tuple(f"{s}://" for s in _LUD17_SCHEMES)):
        url = from_lud17(trimmed)
        return url if is_allowed_service_url(url) else None
    if is_lightning_address(trimmed) or _is_loopback_lightning_address(trimmed):
        return _ln_address_to_url(trimmed)
    if re.match(r"^https?://", trimmed, re.I):
        return trimmed if is_allowed_service_url(trimmed) else None
    return None


def mint_address_url(pay_url: str) -> str | None:
    """LUD-25 mint address (experimental): the withdraw-side mirror of a
    payRequest URL. Derived from the resolved payRequest URL rather than
    guessed - None for anything not at the conventional well-known path."""
    try:
        parsed = urlparse(pay_url)
    except ValueError:
        return None
    if not parsed.scheme or not parsed.netloc:
        return None
    match = _LNURLP_PATH_RE.match(parsed.path)
    if not match:
        return None
    return f"{parsed.scheme}://{parsed.netloc}{match.group(1)}lnurlw/{match.group(2)}"


def lightning_address_username(pay_url: str) -> str | None:
    try:
        match = _LNURLP_PATH_RE.match(urlparse(pay_url).path)
    except ValueError:
        return None
    return match.group(2) if match else None


def server_of(url: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return url
    return parsed.netloc or url
