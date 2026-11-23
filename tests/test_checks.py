from datetime import datetime, timedelta

from secops import checks, incidents
from secops.data import load
from tests.helpers import DATA
from tests.helpers import auth, ds, fw, hr, update, user

T = datetime(2026, 11, 12, 23, 50)


def base(**extra):
    parts = dict(users=[user("a", emp="E1")], hr=[hr("E1")],
                 entitlements=[{"username": "a", "system": "CRM", "permission": "customer_view"}],
                 auth=[auth(datetime(2026, 11, 10, 8), "a")],
                 firewall=[fw(datetime(2026, 11, 10, 8), "10.20.10.5", "10.10.100.20", 443, "ALLOW")],
                 cdr=[{"call_id": "C1", "start_time": "2026-11-10 09:00:00", "extension": "4001",
                       "dialled_number": "+13065550100", "duration_sec": "60", "disposition": "ANSWERED",
                       "trunk": "T1"}],
                 customer=[{"event_id": "EV1", "timestamp": "2026-11-10 09:00:00", "customer_id": "C1",
                            "event_type": "LOGIN", "channel": "Online", "agent": "", "verification": "PASSWORD"}])
    parts.update(extra)
    return ds(**parts)


def test_committed_data_is_clean():
    assert checks.check_inputs(load(DATA)) == []


def test_clean_minimal_dataset():
    assert checks.check_inputs(base()) == []


def test_bad_ip_and_result():
    d = base(auth=[dict(auth(datetime(2026, 11, 10, 8), "a"), src_ip="10.20.300.1", result="MAYBE")])
    errors = checks.check_inputs(d)
    assert any("bad IP" in e for e in errors) and any("SUCCESS or FAILURE" in e for e in errors)


def test_directory_older_than_sign_in_log():
    d = base(users=[user("a", emp="E1", last="2026-11-01 08:00:00")])
    assert any("last_logon is older" in e for e in checks.check_inputs(d))


def test_entitlement_for_unknown_user():
    d = base(entitlements=[{"username": "ghost", "system": "CRM", "permission": "customer_view"}])
    assert any("ghost" in e for e in checks.check_inputs(d))


def incs():
    return incidents.build([{"alert_id": "ALR-0001", "rule_id": "DET-02", "entity_type": "user", "entity": "a",
                             "severity": "High", "_first": T, "_detected": T}])


def test_update_for_unknown_incident():
    errors = checks.check_updates(ds(updates=[update("INC-0099", T, "Closed")]).updates, incs(), T + timedelta(days=1))
    assert any("no such incident" in e for e in errors)


def test_status_cannot_go_backwards_or_predate_the_incident():
    ups = ds(updates=[update("INC-0001", T - timedelta(hours=1), "Acknowledged"),
                      update("INC-0001", T + timedelta(hours=1), "Closed"),
                      update("INC-0001", T + timedelta(hours=2), "Acknowledged")]).updates
    errors = checks.check_updates(ups, incs(), T + timedelta(days=1))
    assert any("earlier than the incident" in e for e in errors)
    assert any("goes backwards" in e for e in errors)
