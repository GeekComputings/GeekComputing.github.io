"""Target and credential models.

Credentials live only in memory for the duration of a run; Secaria never
writes them to disk. A :class:`Target` also carries the authorization flag
so the engine can refuse to touch hosts that were not explicitly scoped in.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class Credential:
    """A username/password (optionally with domain) used for read-only auth.

    Prefer pulling the secret from the environment over passing it on the
    command line. ``from_env`` reads ``SECARIA_USERNAME`` / ``SECARIA_PASSWORD``
    / ``SECARIA_DOMAIN`` by default.
    """

    username: str
    password: str
    domain: Optional[str] = None

    @classmethod
    def from_env(cls, prefix: str = "SECARIA") -> Optional["Credential"]:
        user = os.environ.get(f"{prefix}_USERNAME")
        pw = os.environ.get(f"{prefix}_PASSWORD")
        if not user or not pw:
            return None
        return cls(username=user, password=pw, domain=os.environ.get(f"{prefix}_DOMAIN"))

    @property
    def upn(self) -> str:
        """user@domain form when a domain is set, otherwise the bare user."""
        if self.domain:
            return f"{self.username}@{self.domain}"
        return self.username

    def __repr__(self) -> str:  # never leak the secret in logs/tracebacks
        return f"Credential(username={self.username!r}, domain={self.domain!r}, password=***)"


@dataclass
class Target:
    """A single host to assess.

    ``authorized`` must be explicitly True for the engine to connect. This is
    a deliberate guardrail: an agentless tool with domain creds should never
    reach out to a host that was not signed off for testing.
    """

    host: str
    kind: str = "ad"  # one of: ad, windows, exchange, linux
    port: Optional[int] = None
    use_ssl: bool = True
    authorized: bool = False
    credential: Optional[Credential] = None

    def require_authorized(self) -> None:
        if not self.authorized:
            raise PermissionError(
                f"target {self.host!r} is not marked authorized; refusing to connect. "
                "Add it to your scope file or pass --i-have-authorization."
            )
