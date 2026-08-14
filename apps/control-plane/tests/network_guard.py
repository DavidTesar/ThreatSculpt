"""Block outbound sockets for the whole suite.

The mirror sync needs a real HTTP client in ``src/``, which retires the old
guarantee — "there is no HTTP client anywhere in ``src/``, so nothing can reach
nvd.nist.gov even by accident". That guarantee was an absence, and absences stop
holding the moment somebody adds an import.

This is the replacement, and it is strictly stronger: it covers httpx, requests,
urllib, smtplib, a raw ``socket``, and anything a future workstream adds,
because it works at the syscall boundary rather than at the import.

Loopback and unix sockets stay open — the suite talks to PostgreSQL over both,
and an SMTP delivery test runs a real ``aiosmtpd`` on localhost. Everything else
raises ``OutboundNetworkBlockedError``, which names the address so a test that
accidentally reaches for the internet says so instead of hanging until a timeout.

Name resolution is blocked as well as connection. Resolving
``services.nvd.nist.gov`` is itself traffic that leaves this machine, and it
tells a resolver operator exactly which feeds the suite would have called.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Final

#: Hostnames that resolve to loopback but never reach the resolver here, so they
#: are matched textually before any address parsing.
LOCAL_HOSTNAMES: Final = frozenset({"localhost", "localhost.localdomain", "", "::1"})


class OutboundNetworkBlockedError(RuntimeError):
    """A test tried to open a socket to somewhere that is not this machine."""


def is_local_address(address: Any) -> bool:
    """True for loopback, unix sockets, and anything with no routable host."""
    if not isinstance(address, tuple) or not address:
        # AF_UNIX addresses are `str`/`bytes` — the PostgreSQL socket path.
        return True
    host = address[0]
    # anyio IDNA-encodes the hostname before resolving it, so the guard sees
    # `b'services.nvd.nist.gov'` rather than a `str`. Treating that as "not a
    # hostname, therefore harmless" is how a DNS lookup for a real feed slips
    # through — it did, until this decode was added.
    if isinstance(host, bytes | bytearray):
        host = bytes(host).decode("ascii", errors="replace")
    if not isinstance(host, str):
        # AF_NETLINK and AF_PACKET address tuples are integers and never leave
        # the machine. Nothing that reaches the internet arrives here.
        return True
    if host in LOCAL_HOSTNAMES:
        return True
    try:
        parsed = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        # A name the guard cannot resolve to a literal is treated as remote.
        # Erring towards blocking is the whole point: a mistake here fails a
        # test loudly, while the opposite mistake lets a suite hit the internet.
        return False
    return parsed.is_loopback


def _blocked(address: Any) -> OutboundNetworkBlockedError:
    return OutboundNetworkBlockedError(
        f"outbound network access to {address!r} is blocked in tests. "
        "Inject a fake JsonFetcher instead of reaching a real feed."
    )


def flatten_error(error: BaseException) -> str:
    """Every message in a possibly-grouped exception.

    ``anyio`` runs happy-eyeballs connection attempts concurrently and reports
    their failures as an ``ExceptionGroup``, so the guard's message is nested
    rather than at the top. Tests assert on this rather than on the type.
    """
    if isinstance(error, BaseExceptionGroup):
        return " | ".join(flatten_error(nested) for nested in error.exceptions)
    return str(error)


@contextmanager
def block_outbound_network() -> Iterator[None]:
    """Patch the chokepoints every Python network client eventually goes through."""
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_create_connection = socket.create_connection
    real_getaddrinfo = socket.getaddrinfo

    def guarded_connect(self: socket.socket, address: Any) -> Any:
        if not is_local_address(address):
            raise _blocked(address)
        return real_connect(self, address)

    def guarded_connect_ex(self: socket.socket, address: Any) -> Any:
        if not is_local_address(address):
            raise _blocked(address)
        return real_connect_ex(self, address)

    def guarded_create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
        if not is_local_address(address):
            raise _blocked(address)
        return real_create_connection(address, *args, **kwargs)

    def guarded_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
        if host is not None and not is_local_address((host, port)):
            raise _blocked((host, port))
        return real_getaddrinfo(host, port, *args, **kwargs)

    # Monkey-patching stdlib callables is exactly what mypy is right to dislike
    # and exactly what a guard at the syscall boundary has to do.
    socket.socket.connect = guarded_connect  # type: ignore[assignment,method-assign]
    socket.socket.connect_ex = guarded_connect_ex  # type: ignore[assignment,method-assign]
    socket.create_connection = guarded_create_connection
    socket.getaddrinfo = guarded_getaddrinfo
    try:
        yield
    finally:
        socket.socket.connect = real_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = real_connect_ex  # type: ignore[method-assign]
        socket.create_connection = real_create_connection
        socket.getaddrinfo = real_getaddrinfo
