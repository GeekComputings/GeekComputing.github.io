"""Active Directory collector (read-only, over LDAP).

Live collection uses ``ldap3`` and is intentionally read-only: it issues
SEARCH operations only, never MODIFY. ``ldap3`` is imported lazily so the
rest of Secaria — including offline evaluation against a saved facts file —
works without it installed.

Facts schema (the contract rules depend on)
-------------------------------------------
``domain``                       str   — domain DNS name
``password_policy.min_length``   int
``password_policy.history``      int   — passwords remembered
``password_policy.lockout_threshold`` int  — 0 means no lockout
``password_policy.complexity``   bool
``password_policy.reversible_encryption`` bool
``password_policy.max_age_days`` int
``krbtgt.password_age_days``     int
``machine_account_quota``        int
``domain_admins.count``          int
``privileged_stale_accounts``    list[str]  — sAMAccountNames inactive > threshold
``unconstrained_delegation``     list[str]  — objects trusted for delegation
``privileged_never_expires``     list[str]  — privileged accounts, pwd never expires
"""

from __future__ import annotations

import datetime
from typing import Any

from ..core.target import Target
from .base import Collector

# userAccountControl bit flags we care about.
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_ACCOUNTDISABLE = 0x2

# Windows FILETIME epoch (1601-01-01) to Unix epoch, in 100ns intervals.
_FILETIME_OFFSET = 116444736000000000
_HUNDREDS_OF_NS = 10_000_000

STALE_DAYS_DEFAULT = 90


def filetime_to_datetime(filetime: int) -> datetime.datetime | None:
    """Convert an AD FILETIME integer to an aware UTC datetime, or None."""
    if not filetime or filetime in (0, 0x7FFFFFFFFFFFFFFF):
        return None
    unix = (filetime - _FILETIME_OFFSET) / _HUNDREDS_OF_NS
    return datetime.datetime.fromtimestamp(unix, tz=datetime.timezone.utc)


def days_since(when: datetime.datetime | None) -> int | None:
    if when is None:
        return None
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    return (now - when).days


class ActiveDirectoryCollector(Collector):
    """Gather AD posture facts over LDAP.

    This class focuses on *live* collection. Offline evaluation against a
    previously captured facts file is handled by the engine, so you can
    develop and test rules without a domain controller.
    """

    kind = "ad"

    def __init__(self, target: Target, stale_days: int = STALE_DAYS_DEFAULT):
        super().__init__(target)
        self.stale_days = stale_days

    def collect(self) -> dict[str, Any]:  # pragma: no cover - needs live AD
        self.target.require_authorized()
        conn, base_dn = self._connect()
        try:
            facts: dict[str, Any] = {"domain": self.target.host}
            facts.update(self._password_policy(conn, base_dn))
            facts["krbtgt"] = self._krbtgt(conn, base_dn)
            facts["machine_account_quota"] = self._machine_quota(conn, base_dn)
            priv = self._privileged_accounts(conn, base_dn)
            facts["domain_admins"] = {"count": priv["da_count"]}
            facts["privileged_stale_accounts"] = priv["stale"]
            facts["privileged_never_expires"] = priv["never_expires"]
            facts["unconstrained_delegation"] = self._unconstrained_delegation(conn, base_dn)
            return facts
        finally:
            conn.unbind()

    # -- connection -------------------------------------------------------
    def _connect(self):  # pragma: no cover - needs live AD
        try:
            from ldap3 import ALL, Connection, Server
        except ImportError as exc:
            raise RuntimeError(
                "ldap3 is required for live AD collection. Install it, or run "
                "with --facts to evaluate a saved facts file offline."
            ) from exc

        cred = self.target.credential
        if cred is None:
            raise ValueError("AD collection requires a credential")
        port = self.target.port or (636 if self.target.use_ssl else 389)
        server = Server(self.target.host, port=port, use_ssl=self.target.use_ssl, get_info=ALL)
        conn = Connection(server, user=cred.upn, password=cred.password, auto_bind=True)
        base_dn = server.info.other.get("defaultNamingContext", [None])[0]
        if not base_dn:
            raise RuntimeError("could not determine domain base DN from RootDSE")
        return conn, base_dn

    # -- individual fact gatherers (read-only searches) -------------------
    def _password_policy(self, conn, base_dn) -> dict[str, Any]:  # pragma: no cover
        conn.search(
            base_dn,
            "(objectClass=domain)",
            attributes=[
                "minPwdLength",
                "pwdHistoryLength",
                "lockoutThreshold",
                "pwdProperties",
                "maxPwdAge",
            ],
        )
        entry = conn.entries[0]
        pwd_props = int(entry.pwdProperties.value or 0)
        max_age_ticks = abs(int(entry.maxPwdAge.value or 0))
        max_age_days = int(max_age_ticks / _HUNDREDS_OF_NS / 86400) if max_age_ticks else 0
        return {
            "password_policy": {
                "min_length": int(entry.minPwdLength.value or 0),
                "history": int(entry.pwdHistoryLength.value or 0),
                "lockout_threshold": int(entry.lockoutThreshold.value or 0),
                "complexity": bool(pwd_props & 0x1),
                "reversible_encryption": bool(pwd_props & 0x10),
                "max_age_days": max_age_days,
            }
        }

    def _krbtgt(self, conn, base_dn) -> dict[str, Any]:  # pragma: no cover
        conn.search(base_dn, "(sAMAccountName=krbtgt)", attributes=["pwdLastSet"])
        last_set = filetime_to_datetime(int(conn.entries[0].pwdLastSet.value or 0))
        return {"password_age_days": days_since(last_set)}

    def _machine_quota(self, conn, base_dn) -> int:  # pragma: no cover
        conn.search(base_dn, "(objectClass=domain)", attributes=["ms-DS-MachineAccountQuota"])
        return int(conn.entries[0]["ms-DS-MachineAccountQuota"].value or 0)

    def _privileged_accounts(self, conn, base_dn) -> dict[str, Any]:  # pragma: no cover
        conn.search(
            base_dn,
            "(&(objectCategory=user)(memberOf=CN=Domain Admins,CN=Users,%s))" % base_dn,
            attributes=["sAMAccountName", "userAccountControl", "lastLogonTimestamp"],
        )
        stale, never_expires = [], []
        for e in conn.entries:
            name = str(e.sAMAccountName.value)
            uac = int(e.userAccountControl.value or 0)
            if uac & UAC_DONT_EXPIRE_PASSWORD:
                never_expires.append(name)
            last = filetime_to_datetime(int(e.lastLogonTimestamp.value or 0))
            d = days_since(last)
            if d is not None and d > self.stale_days:
                stale.append(name)
        return {"da_count": len(conn.entries), "stale": stale, "never_expires": never_expires}

    def _unconstrained_delegation(self, conn, base_dn) -> list[str]:  # pragma: no cover
        conn.search(
            base_dn,
            "(userAccountControl:1.2.840.113556.1.4.803:=%d)" % UAC_TRUSTED_FOR_DELEGATION,
            attributes=["sAMAccountName"],
        )
        # Domain controllers are expected to have this; exclude them by filter
        # in a fuller implementation. Reported as-is for the narrow slice.
        return [str(e.sAMAccountName.value) for e in conn.entries]
