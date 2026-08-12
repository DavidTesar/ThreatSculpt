"""Command-line entry point.

There is deliberately no ``--api-key`` and no ``--enrollment-token`` flag. Anything in
argv is visible to every user on the host via ``ps``, so secrets arrive only from the
environment or from a 0600 file. ``_reject_secret_arguments`` additionally refuses to
start if a credential was pasted onto the command line anyway.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

from . import AGENT_VERSION
from .api.client import ControlPlaneClient
from .config import AgentSettings, load_settings
from .daemon import EXIT_FATAL, EXIT_OK, AgentDaemon
from .enrollment import ensure_enrolled
from .errors import AgentError
from .keystore import KeyStore
from .logging_setup import configure_logging
from .nmap.runner import detect_nmap_version

log = logging.getLogger("threatsculpt_agent")

_SECRET_PREFIXES = ("tsa_", "tse_")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatsculpt-agent",
        description="ThreatSculpt on-prem scan agent. Polls the control plane, runs nmap "
        "locally, submits observations. Secrets come from the environment or a 0600 file, "
        "never from the command line.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="TOML config file (default: /etc/threatsculpt/agent.toml)",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate configuration and the local allowlist, then exit without polling",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="run a single poll cycle and exit (useful for cron-style operation and smoke tests)",
    )
    parser.add_argument("--version", action="version", version=AGENT_VERSION)
    return parser


def _reject_secret_arguments(argv: list[str]) -> None:
    for item in argv:
        value = item.split("=", 1)[-1]
        if value.startswith(_SECRET_PREFIXES):
            raise SystemExit(
                "refusing to start: a credential was passed on the command line, where "
                "`ps` exposes it to every user on this host. Use TS_AGENT_API_KEY / "
                "TS_AGENT_ENROLLMENT_TOKEN or a 0600 file instead."
            )


def _describe_config(settings: AgentSettings) -> str:
    allowlist = ", ".join(str(net) for net in settings.allowlist) or "<empty>"
    return (
        f"agent_name={settings.agent_name} control_plane={settings.control_plane_url} "
        f"allowlist=[{allowlist}] nmap={settings.nmap_path} "
        f"key_file={settings.resolved_api_key_file}"
    )


async def async_main(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    configure_logging(settings.log_level)
    log.info("threatsculpt scan agent %s starting: %s", AGENT_VERSION, _describe_config(settings))

    if not settings.allowlist:
        log.error(
            "local allowlist is empty: every job would be rejected. Configure `allowlist` "
            "with the CIDRs this agent is authorised to scan."
        )
        return EXIT_FATAL

    if args.check_config:
        log.info("configuration is valid")
        return EXIT_OK

    keystore = KeyStore(settings.resolved_api_key_file)
    nmap_version = await detect_nmap_version(settings.nmap_path)
    log.info("local nmap version: %s", nmap_version)

    async with ControlPlaneClient(
        settings.control_plane_url,
        timeout=settings.request_timeout_seconds,
        verify=settings.verify_tls,
    ) as anonymous:
        outcome = await ensure_enrolled(settings, anonymous, keystore)
        authenticated = anonymous.with_api_key(outcome.api_key)
        daemon = AgentDaemon.build(settings, authenticated, keystore, nmap_version)
        _install_signal_handlers(daemon)
        return await daemon.run(max_cycles=1 if args.once else None)


def _install_signal_handlers(daemon: AgentDaemon) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, daemon.request_shutdown, sig.name)
        except (NotImplementedError, RuntimeError):  # pragma: no cover - non-POSIX
            log.warning("cannot install a %s handler on this platform", sig.name)


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    _reject_secret_arguments(raw_args)
    args = build_parser().parse_args(raw_args)
    try:
        return asyncio.run(async_main(args))
    except AgentError as exc:
        configure_logging("INFO")
        log.error("%s", exc)
        return EXIT_FATAL
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        log.info("interrupted")
        return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
