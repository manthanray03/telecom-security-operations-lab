from datetime import datetime, timedelta

from secops import incidents
from tests.helpers import ds, update


def alert(n, rule, entity, sev, at):
    return {"alert_id": f"ALR-{n:04d}", "rule_id": rule, "entity_type": "user", "entity": entity, "severity": sev,
            "_first": at - timedelta(minutes=10), "_detected": at}


T = datetime(2026, 11, 12, 23, 50)


def test_alerts_for_same_entity_merge_and_take_the_worst_severity():
    incs = incidents.build([alert(1, "DET-02", "dmorin", "High", T), alert(2, "DET-03", "dmorin", "Critical", T)])
    assert len(incs) == 1
    assert incs[0]["severity"] == "Critical" and incs[0]["rules"] == "DET-02 DET-03"


def test_alerts_more_than_24_hours_apart_stay_separate():
    incs = incidents.build([alert(1, "DET-03", "a", "High", T), alert(2, "DET-03", "a", "High", T + timedelta(hours=25))])
    assert [i["incident_id"] for i in incs] == ["INC-0001", "INC-0002"]


def test_time_to_detect_counts_from_first_event():
    [inc] = incidents.build([alert(1, "DET-03", "a", "High", T)])
    assert inc["minutes_to_detect"] == 10


def run(updates, as_of, sev="Critical"):
    incs = incidents.build([alert(1, "DET-02", "a", sev, T)])
    incidents.apply_updates(incs, ds(updates=updates).updates, as_of)
    return incs[0]


def test_sla_met():
    inc = run([update("INC-0001", T + timedelta(minutes=10), "Acknowledged"),
               update("INC-0001", T + timedelta(hours=3), "Contained")], T + timedelta(days=1))
    assert (inc["ack_met"], inc["contain_met"], inc["status"]) == ("Yes", "Yes", "Contained")
    assert inc["minutes_to_ack"] == 10 and inc["minutes_to_contain"] == 180


def test_sla_missed():
    inc = run([update("INC-0001", T + timedelta(minutes=30), "Acknowledged"),
               update("INC-0001", T + timedelta(hours=5), "Closed")], T + timedelta(days=1))
    assert (inc["ack_met"], inc["contain_met"]) == ("No", "No")
    assert inc["contained_at"] == inc["closed_at"]  # closing also counts as contained


def test_no_updates_is_overdue_or_pending():
    assert run([], T + timedelta(hours=5))["contain_met"] == "Overdue"
    assert run([], T + timedelta(hours=2), sev="Medium")["contain_met"] == "Pending"


def test_updates_after_report_date_are_ignored():
    inc = run([update("INC-0001", T + timedelta(days=3), "Closed")], T + timedelta(days=1))
    assert inc["status"] == "Open"
