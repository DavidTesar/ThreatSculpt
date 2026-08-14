"""Proof that the suite still cannot reach the internet.

Before the mirror could be synced, that was guaranteed by there being no HTTP
client in ``src/`` at all — which is also why the mirror could not be synced.
The guarantee is now two mechanisms instead of one absence:

1. **One module may import an HTTP client.** Anything else under ``enrichment/``
   that grows an httpx import fails ``test_only_the_http_module_imports_httpx``,
   and takes the injected-fetcher seam with it if it does not.
2. **The suite runs behind a socket block** (``conftest._no_outbound_network``),
   which covers httpx, urllib, requests, smtplib and a bare socket alike, and
   covers modules nobody has written yet.

The tests below deliberately attempt outbound connections. They pass by being
refused; if the guard ever stops working they will reach the real internet and
fail on the assertion rather than silently doing nothing.
"""

from __future__ import annotations

import ast
import socket
import urllib.request
from pathlib import Path

import httpx
import pytest

from tests.network_guard import OutboundNetworkBlockedError, flatten_error, is_local_address

ENRICHMENT_DIR = Path(__file__).resolve().parents[1] / "src" / "threatsculpt" / "enrichment"

#: The single module allowed to import an HTTP client, and the reason the rest
#: of the package can stay testable without one.
HTTP_CLIENT_MODULE = "http.py"

HTTP_CLIENT_PACKAGES = frozenset({"httpx", "requests", "aiohttp", "urllib3"})


def imported_roots(source: str) -> set[str]:
    """Top-level package names imported by a module, in either import form."""
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


# --- mechanism 1: the import boundary ---------------------------------------


def test_only_the_http_module_imports_httpx() -> None:
    offenders = {
        path.name: sorted(imported_roots(path.read_text()) & HTTP_CLIENT_PACKAGES)
        for path in sorted(ENRICHMENT_DIR.glob("*.py"))
        if path.name != HTTP_CLIENT_MODULE
    }
    assert {name: found for name, found in offenders.items() if found} == {}


def test_the_http_module_is_the_one_that_does() -> None:
    """Guards the guard: a typo'd filename would make the test above vacuous."""
    source = (ENRICHMENT_DIR / HTTP_CLIENT_MODULE).read_text()
    assert "httpx" in imported_roots(source)


# --- mechanism 2: the socket block ------------------------------------------


async def test_httpx_cannot_reach_the_real_nvd() -> None:
    """The exact call the production sync makes, refused before it leaves."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        with pytest.raises(BaseException) as caught:
            await client.get("https://services.nvd.nist.gov/rest/json/cves/2.0")
    assert "blocked in tests" in flatten_error(caught.value)


def test_a_bare_socket_cannot_leave_this_machine() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5.0)
        with pytest.raises(OutboundNetworkBlockedError):
            sock.connect(("1.1.1.1", 80))


def test_urllib_cannot_leave_this_machine() -> None:
    with pytest.raises(OutboundNetworkBlockedError):
        urllib.request.urlopen("http://1.1.1.1/", timeout=5.0)


def test_loopback_and_unix_sockets_stay_open() -> None:
    """The suite talks to PostgreSQL and a local SMTP server; both must survive."""
    assert is_local_address(("127.0.0.1", 5432))
    assert is_local_address(("::1", 5432))
    assert is_local_address(("localhost", 25))
    assert is_local_address("/tmp/.s.PGSQL.5432")  # noqa: S108 - the real socket path
    assert not is_local_address(("services.nvd.nist.gov", 443))
    assert not is_local_address(("1.1.1.1", 80))


def test_an_idna_encoded_hostname_is_not_mistaken_for_a_local_one() -> None:
    """anyio resolves `b'host'`, not `'host'`. That bytes host once slipped past."""
    assert not is_local_address((b"services.nvd.nist.gov", 443))
    assert is_local_address((b"localhost", 5432))


def test_dns_for_a_remote_feed_is_refused_before_any_packet_leaves() -> None:
    with pytest.raises(OutboundNetworkBlockedError):
        socket.getaddrinfo("services.nvd.nist.gov", 443)


def test_dns_for_this_machine_still_works() -> None:
    """PostgreSQL and the local SMTP server are reached by name in places."""
    assert socket.getaddrinfo("localhost", 5432)
