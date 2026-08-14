#!/usr/bin/env python3
"""Write the control plane's OpenAPI schema to ``apps/web/openapi.json``.

The schema is the contract the web client's types are generated from. FastAPI
derives it from the route signatures and Pydantic models, so it is produced by
the same code that serves the responses — which is the whole reason it is
authoritative and this document is not hand-maintained.

The app is *constructed*, never served: ``create_app()`` wires routes and
middleware, while every database connection is opened by the lifespan handler,
which never runs here. So this needs no database, no port and no real
credentials — the settings below are throwaway values chosen only to satisfy
validation.

Run it with the control plane's interpreter, which has the app importable:

    apps/control-plane/.venv/bin/python apps/web/scripts/dump_openapi.py

or, from ``apps/web``, ``npm run openapi:dump``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CONTROL_PLANE_SRC = REPO_ROOT / "apps" / "control-plane" / "src"
OUTPUT_PATH = REPO_ROOT / "apps" / "web" / "openapi.json"

# Throwaway settings. Nothing here is a credential: no connection is opened and
# no token is signed. They exist because Settings validates eagerly, and eager
# validation is the behaviour we want in production.
THROWAWAY_SETTINGS = {
    "environment": "test",
    "database_url": "postgresql+psycopg://schema-dump:schema-dump@127.0.0.1:5432/schema-dump",
    "jwt_secret": "openapi-schema-dump-not-a-real-signing-key",
    # Boot refuses undeliverable email unless this is explicit; see config.py.
    "email_delivery": "memory",
    "allow_undeliverable_email": True,
    "log_level": "ERROR",
}


def build_schema() -> dict[str, object]:
    if CONTROL_PLANE_SRC.is_dir():
        sys.path.insert(0, str(CONTROL_PLANE_SRC))

    try:
        from threatsculpt.app import create_app
        from threatsculpt.config import Settings
    except ImportError as exc:  # pragma: no cover - operator-facing guidance
        raise SystemExit(
            f"Could not import the control plane ({exc}).\n"
            "Run this with the control plane's interpreter, e.g.\n"
            "  apps/control-plane/.venv/bin/python apps/web/scripts/dump_openapi.py"
        ) from exc

    app = create_app(Settings(**THROWAWAY_SETTINGS))  # type: ignore[arg-type]
    schema = app.openapi()
    if not schema.get("paths"):
        raise SystemExit("The generated schema has no paths; refusing to write it.")
    return schema


def main() -> int:
    schema = build_schema()
    # sort_keys so an unrelated reordering inside FastAPI cannot show up as a
    # diff, and a trailing newline so the file is well-formed for git.
    OUTPUT_PATH.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT_PATH.relative_to(REPO_ROOT)} ({len(schema['paths'])} paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
