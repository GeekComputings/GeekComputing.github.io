"""Collectors: read-only, agentless fact gatherers.

Collectors only *gather*; they never judge. The same facts can be evaluated
by CIS rules and STIG rules alike. This separation is what lets one scan
serve multiple compliance lenses.
"""

from .base import Collector  # noqa: F401
