"""The collector contract."""

from __future__ import annotations

import abc
from typing import Any

from ..core.target import Target


class Collector(abc.ABC):
    """Connects to a target and returns a flat-ish dict of facts.

    Implementations must be strictly read-only. The returned facts dict is the
    only interface rules depend on, so its shape is effectively a contract —
    document the keys you emit alongside the rules that consume them.
    """

    #: short identifier matching ``Target.kind``
    kind: str = "base"

    def __init__(self, target: Target):
        self.target = target

    @abc.abstractmethod
    def collect(self) -> dict[str, Any]:
        """Connect (read-only) and return collected facts."""
        raise NotImplementedError
