import os

import pytest

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "secaria", "rules", "ad")


@pytest.fixture
def rules_dir() -> str:
    return os.path.abspath(RULES_DIR)


@pytest.fixture
def clean_facts() -> dict:
    """A well-configured domain: every control should PASS."""
    return {
        "domain": "secure.example.com",
        "password_policy": {
            "min_length": 16,
            "history": 24,
            "lockout_threshold": 5,
            "complexity": True,
            "reversible_encryption": False,
            "max_age_days": 180,
        },
        "krbtgt": {"password_age_days": 30},
        "machine_account_quota": 0,
        "domain_admins": {"count": 3},
        "privileged_stale_accounts": [],
        "unconstrained_delegation": [],
        "privileged_never_expires": [],
    }


@pytest.fixture
def weak_facts() -> dict:
    """A poorly-configured domain: many controls should FAIL."""
    return {
        "domain": "weak.example.com",
        "password_policy": {
            "min_length": 7,
            "history": 5,
            "lockout_threshold": 0,
            "complexity": False,
            "reversible_encryption": True,
            "max_age_days": 0,
        },
        "krbtgt": {"password_age_days": 1200},
        "machine_account_quota": 10,
        "domain_admins": {"count": 25},
        "privileged_stale_accounts": ["svc-old", "admin.legacy"],
        "unconstrained_delegation": ["WEB01$", "APP02$"],
        "privileged_never_expires": ["Administrator"],
    }
