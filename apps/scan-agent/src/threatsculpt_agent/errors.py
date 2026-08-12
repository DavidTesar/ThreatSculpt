"""Exception hierarchy for the scan agent.

Every failure path in the agent raises one of these; nothing is swallowed silently.
"""

from __future__ import annotations


class AgentError(Exception):
    """Base class for all agent errors."""


class ConfigError(AgentError):
    """Configuration is missing, malformed, or refuses to load."""


class KeyStoreError(AgentError):
    """The API key file cannot be read or written safely."""


class InsecureKeyPermissionsError(KeyStoreError):
    """The API key file is readable by users other than the agent."""


class EnrollmentError(AgentError):
    """Enrollment could not be completed."""


class InvalidNetworkError(AgentError):
    """A CIDR/address string could not be parsed."""


class UnknownProfileError(AgentError):
    """A job asked for a scan profile the agent does not know."""


class NmapError(AgentError):
    """Base class for nmap invocation failures."""


class NmapTimeoutError(NmapError):
    """nmap exceeded its hard timeout and was killed."""


class NmapFailedError(NmapError):
    """nmap exited non-zero."""


class NmapOutputTooLargeError(NmapError):
    """nmap produced more XML than the agent is willing to buffer."""


class XmlParseError(AgentError):
    """nmap XML output could not be parsed."""


class SubmissionTooLargeError(AgentError):
    """A single host observation cannot be made to fit under the payload cap."""


class ApiError(AgentError):
    """Base class for control-plane transport/protocol errors."""


class TransportError(ApiError):
    """The control plane could not be reached."""


class AuthRevokedError(ApiError):
    """401, or a heartbeat carrying revoked=true. The agent must wipe its key and exit."""


class JobConflictError(ApiError):
    """409 — the job is no longer claimable by this agent."""


class RateLimitedError(ApiError):
    """429. Carries the server-supplied Retry-After, in seconds, when present."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ServerError(ApiError):
    """5xx — retryable."""


class ClientError(ApiError):
    """A non-retryable 4xx other than 401/409/429."""
