"""Entrypoint.

    uvicorn main:app --host 0.0.0.0 --port 8000
    python main.py                      # development convenience

The ASGI object is created at import so a process manager can reference
``main:app`` directly; database connections are opened by the lifespan handler,
not at import, so importing this module never touches the network.
"""

from __future__ import annotations

from threatsculpt.app import create_app

app = create_app()


def main() -> None:
    import uvicorn

    from threatsculpt.config import get_settings

    settings = get_settings()
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=settings.environment == "development",
        log_config=None,  # our JSON formatter owns logging
    )


if __name__ == "__main__":
    main()
