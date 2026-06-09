"""Human-readable enrichment for framework reference IDs.

Only the techniques referenced by the current ruleset are listed; extend the
map as rules are added. ``describe_attack`` degrades gracefully to the bare
ID for anything unknown so reports never break on a missing entry.
"""

from __future__ import annotations

# MITRE ATT&CK technique id -> short name
_ATTACK_NAMES = {
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1558.001": "Golden Ticket",
    "T1558.003": "Kerberoasting",
    "T1078": "Valid Accounts",
    "T1078.002": "Valid Accounts: Domain Accounts",
    "T1098": "Account Manipulation",
    "T1187": "Forced Authentication",
    "T1003": "OS Credential Dumping",
    "T1556": "Modify Authentication Process",
}


def describe_attack(technique_id: str) -> str:
    name = _ATTACK_NAMES.get(technique_id)
    return f"{technique_id} — {name}" if name else technique_id


def attack_url(technique_id: str) -> str:
    """Canonical MITRE ATT&CK URL for a technique or sub-technique id."""
    base, _, sub = technique_id.partition(".")
    if sub:
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/{base}/"
