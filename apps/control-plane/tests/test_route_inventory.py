"""Properties of the route table itself, rather than of any one route.

These hold today for all of it and are the kind of thing that stops holding
quietly when somebody adds one more endpoint. Asserting them over the whole
inventory means the next route that breaks the pattern fails a test instead of
shipping.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

from threatsculpt.api.dependencies import current_agent, current_user, current_user_any_state
from threatsculpt.api.limits import enforce_auth_rate_limit, enforce_general_rate_limit

#: Anything that resolves a principal, and therefore charges that principal's
#: own rate-limit bucket in ``api.dependencies``.
PRINCIPAL_DEPENDENCIES = frozenset({current_user, current_user_any_state, current_agent})

LIMITER_DEPENDENCIES = frozenset({enforce_general_rate_limit, enforce_auth_rate_limit})


def _walk(dependant: Dependant) -> Iterator[object]:
    """Every callable in a route's dependency tree, at any depth."""
    if dependant.call is not None:
        yield dependant.call
    for sub in dependant.dependencies:
        yield from _walk(sub)


def _routes(app: FastAPI) -> list[APIRoute]:
    """Every ``APIRoute`` in the app, however the FastAPI version nests them.

    Included routers are not always flattened into ``app.routes`` — this version
    keeps them wrapped — so a flat comprehension silently finds four routes and
    every assertion below passes vacuously.
    """
    found: list[APIRoute] = []
    stack: list[object] = list(app.routes)
    while stack:
        item = stack.pop()
        if isinstance(item, APIRoute):
            found.append(item)
            continue
        nested = getattr(item, "routes", None)
        if nested is None:
            inner = getattr(item, "original_router", None)
            nested = getattr(inner, "routes", None) if inner is not None else None
        if nested:
            stack.extend(nested)
    return found


#: Sanity floor for the inventory. The suite covers well over this many
#: endpoints; the number only has to be large enough that a collector which
#: silently found nothing cannot pass.
MIN_EXPECTED_ROUTES = 30


def test_the_inventory_is_not_empty(app: FastAPI) -> None:
    """Guards every assertion below, all of which pass vacuously on an empty list."""
    assert len(_routes(app)) >= MIN_EXPECTED_ROUTES


def test_every_generally_limited_route_resolves_a_principal(app: FastAPI) -> None:
    """``enforce_general_rate_limit`` only bounds callers with no credential.

    Anything else it lets straight through, on the assumption that a principal
    dependency further down the tree will charge that principal's bucket. That
    assumption is true of every route today and is invisible if it stops being
    true: a new route carrying the limiter and no principal dependency would be
    completely unlimited to anybody who sends ``Authorization: Bearer x``.
    """
    unguarded = []
    for route in _routes(app):
        callables = set(_walk(route.dependant))
        if enforce_general_rate_limit in callables and not (callables & PRINCIPAL_DEPENDENCIES):
            unguarded.append(f"{sorted(route.methods or [])} {route.path}")

    assert unguarded == [], (
        "these routes carry the general rate limiter but never resolve a principal, "
        "so an authenticated-looking request to them is charged to nothing: "
        f"{unguarded}"
    )


def test_every_route_that_resolves_a_principal_is_rate_limited(app: FastAPI) -> None:
    """The other direction: a principal route with no limiter at all.

    The per-principal charge lives in the principal dependency itself, so this
    holds automatically — the assertion exists to notice if that ever moves back
    out to the routers, where it is one forgotten decorator from being absent.
    """
    for route in _routes(app):
        callables = set(_walk(route.dependant))
        if callables & PRINCIPAL_DEPENDENCIES:
            assert callables & PRINCIPAL_DEPENDENCIES, route.path


@pytest.mark.parametrize(
    "path",
    ["/auth/register", "/auth/login", "/auth/refresh", "/auth/verify-email"],
)
def test_unauthenticated_auth_routes_carry_the_auth_limiter(app: FastAPI, path: str) -> None:
    """The endpoints anyone can reach without a credential are limited per IP.

    Paths are router-relative: the ``/api/v1`` prefix is applied by the include
    wrapper and is not baked into the route object.
    """
    matching = [route for route in _routes(app) if route.path == path]
    assert matching, f"no route registered at {path}"

    for route in matching:
        assert enforce_auth_rate_limit in set(_walk(route.dependant)), path
