"""Capture real nmap XML through the agent's own runner.

Driven by regenerate.sh. Writing the fixtures with the production code path means a bug in
build_argv shows up as a broken fixture rather than passing tests against invented XML.
"""

from __future__ import annotations

import asyncio
import asyncio.subprocess
from pathlib import Path

from threatsculpt_agent.nmap.runner import NmapRunner, detect_nmap_version
from threatsculpt_agent.nmap.xml_parser import parse_nmap_xml

FIXTURE_DIR = Path(__file__).parent
TARGET = "127.0.0.1"
CAPTURES = (("service", "service-localhost.xml"), ("discovery", "discovery-localhost.xml"))

# With ~1000 ports nmap collapses the closed ones into a single <extraports count="999"/>
# summary, so the top-1000 fixture contains no closed <port> elements to filter. With a
# handful of ports it lists each one individually. Both shapes occur in the field, so one
# fixture is captured with an explicit small port list to exercise the state filter against
# real output. This capture is intentionally not a profile: profiles are the fixed set the
# protocol defines, and this is a parser fixture, not a scan the agent would ever run.
SMALL_PORT_ARGV = (
    "/usr/bin/nmap", "-sS", "-sV", "--version-intensity", "5", "-T3",
    "-p", "22,80,8080", "-oX", "-", TARGET,
)


async def main() -> None:
    runner = NmapRunner(nmap_path=Path("/usr/bin/nmap"), timeout_seconds=900.0)
    print(f"nmap version: {await detect_nmap_version(runner.nmap_path)}")

    for profile, filename in CAPTURES:
        result = await runner.run(TARGET, profile)
        _write(filename, result.stdout, result.duration_seconds)

    process = await asyncio.create_subprocess_exec(
        *SMALL_PORT_ARGV, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, _ = await process.communicate()
    _write("closed-ports-localhost.xml", stdout, 0.0)


def _write(filename: str, payload: bytes, duration: float) -> None:
    (FIXTURE_DIR / filename).write_bytes(payload)
    scan = parse_nmap_xml(payload)
    print(
        f"{filename}: {len(payload)} bytes in {duration:.1f}s -> {scan.hosts_up} host(s) up, "
        f"{sum(len(host.ports) for host in scan.hosts)} submittable port(s)"
    )


if __name__ == "__main__":
    asyncio.run(main())
