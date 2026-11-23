from datetime import date

from secops import access_review
from tests.helpers import ds, hr, user

AS_OF = date(2026, 11, 20)


def checks_for(d, name):
    return [f for f in access_review.review(d, AS_OF) if f["username"] == name]


def test_leaver_with_enabled_account():
    d = ds(users=[user("a", emp="E1")], hr=[hr("E1", "Terminated", "2026-11-10")])
    assert any(f["requirement"] == "AM-02" for f in checks_for(d, "a"))


def test_leaver_inside_grace_period_is_not_flagged():
    d = ds(users=[user("a", emp="E1")], hr=[hr("E1", "Terminated", "2026-11-19")])
    assert not any(f["requirement"] == "AM-02" for f in checks_for(d, "a"))


def test_disabled_accounts_are_ignored():
    d = ds(users=[user("a", emp="E1", status="Disabled", mfa="N", last="2025-01-01 00:00:00")],
           hr=[hr("E1", "Terminated", "2025-01-02")])
    assert access_review.review(d, AS_OF) == []


def test_orphaned_account():
    d = ds(users=[user("contractor")])
    assert [f["requirement"] for f in checks_for(d, "contractor")] == ["AM-01"]


def test_service_accounts_are_not_orphans():
    d = ds(users=[user("svc_backup", kind="service", mfa="NA", last="")])
    assert access_review.review(d, AS_OF) == []


def test_dormant_account():
    d = ds(users=[user("a", emp="E1", last="2026-08-01 10:00:00")], hr=[hr("E1")])
    [f] = checks_for(d, "a")
    assert f["requirement"] == "AM-05" and "2026-08-01" in f["detail"]


def test_privileged_without_mfa_is_high():
    d = ds(users=[user("a", emp="E1", mfa="N")], hr=[hr("E1")],
           entitlements=[{"username": "a", "system": "IAM", "permission": "user_admin"}])
    [f] = checks_for(d, "a")
    assert f["requirement"] == "AM-04" and f["severity"] == "High"


def test_separation_of_duties_conflict():
    d = ds(users=[user("a", emp="E1"), user("b", emp="E2")], hr=[hr("E1"), hr("E2")],
           entitlements=[{"username": "a", "system": "CRM", "permission": "sim_swap_perform"},
                         {"username": "a", "system": "CRM", "permission": "sim_swap_approve"},
                         {"username": "b", "system": "CRM", "permission": "sim_swap_perform"}],
           sod_rules=[{"rule_id": "SOD-04", "permission_a": "sim_swap_perform", "permission_b": "sim_swap_approve",
                       "risk": "x"}])
    assert [f["username"] for f in access_review.review(d, AS_OF)] == ["a"]
