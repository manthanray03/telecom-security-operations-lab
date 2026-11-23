from datetime import datetime, timedelta

from secops import detections
from secops.data import load
from tests.helpers import DATA
from tests.helpers import T0, auth, call, cust, ds, fw, hr, minutes, user


def spray(n_accounts, success_after=False):
    events = [auth(T0 + minutes(i), f"user{i}", "FAILURE", ip="203.0.113.45", city="Regina", app="VPN")
              for i in range(n_accounts)]
    if success_after:
        events.append(auth(T0 + minutes(n_accounts + 5), "user0", "SUCCESS", ip="203.0.113.45", app="VPN"))
    return ds(auth=events, users=[user(f"user{i}") for i in range(n_accounts)])


def test_spray_fires_at_threshold():
    assert len(detections.password_spraying(spray(10))) == 1
    assert detections.password_spraying(spray(9)) == []


def test_spray_with_a_success_is_high():
    [alert] = detections.password_spraying(spray(12, success_after=True))
    assert alert["severity"] == "High"
    assert detections.password_spraying(spray(12))[0]["severity"] == "Medium"


def brute(n_fail, success=True, perms=None, mfa="Y"):
    events = [auth(T0 + timedelta(seconds=40 * i), "dana", "FAILURE", ip="198.51.100.77") for i in range(n_fail)]
    if success:
        events.append(auth(T0 + timedelta(seconds=40 * n_fail + 30), "dana", ip="198.51.100.77", mfa=mfa))
    ents = [{"username": "dana", "system": "NETWORK", "permission": p} for p in (perms or [])]
    return ds(auth=events, users=[user("dana", mfa=mfa)], entitlements=ents)


def test_brute_force_needs_a_success():
    assert detections.brute_force_success(brute(12, success=False)) == []
    assert len(detections.brute_force_success(brute(12))) == 1


def test_brute_force_below_threshold_is_quiet():
    assert detections.brute_force_success(brute(7)) == []


def test_brute_force_on_privileged_account_is_critical():
    [alert] = detections.brute_force_success(brute(10, perms=["firewall_change"], mfa="N"))
    assert alert["severity"] == "Critical"
    assert "no MFA" in alert["evidence"]


def travel(second_city, gap_minutes, history=()):
    events = [auth(T0 - timedelta(days=d + 1), "lee", city=c) for d, c in enumerate(history)]
    events += [auth(T0, "lee", city="Regina"), auth(T0 + minutes(gap_minutes), "lee", city=second_city,
                                                    ip="203.0.113.201")]
    return ds(auth=events, users=[user("lee")])


def test_impossible_travel_fires():
    [alert] = detections.impossible_travel(travel("Singapore", 47))
    assert alert["entity"] == "lee" and "Singapore" in alert["evidence"]


def test_a_real_flight_is_not_impossible_travel():
    assert detections.impossible_travel(travel("Toronto", 330)) == []


def test_short_hops_are_ignored():
    assert detections.impossible_travel(travel("Saskatoon", 10)) == []


def test_returning_to_a_known_city_is_not_flagged():
    # Singapore seen before, so a fast hop back there is a known location.
    assert detections.impossible_travel(travel("Singapore", 47, history=["Singapore"])) == []


def test_terminated_account_sign_in():
    d = ds(users=[user("tc", emp="E1")], hr=[hr("E1", "Terminated", "2026-11-05")],
           auth=[auth(datetime(2026, 11, 5, 16), "tc"), auth(datetime(2026, 11, 8, 19), "tc")])
    [alert] = detections.terminated_account_signin(d)
    assert alert["_trigger"] == datetime(2026, 11, 8, 19)  # the sign-in on the last day is fine


def scan(n_ports, src="192.0.2.77", spread_s=4):
    return ds(firewall=[fw(T0 + timedelta(seconds=spread_s * i), src, "203.0.113.10", 1000 + i)
                        for i in range(n_ports)])


def test_port_scan_threshold():
    assert len(detections.port_scan(scan(25))) == 1
    assert detections.port_scan(scan(24)) == []


def test_slow_scan_outside_window_is_quiet():
    assert detections.port_scan(scan(30, spread_s=20)) == []


def test_internal_scan_is_high():
    [alert] = detections.port_scan(scan(30, src="10.20.20.55"))
    assert alert["severity"] == "High"


def toll(start, number="+53123456", n=8, ext="4471"):
    return ds(cdr=[call(i, start + minutes(5 * i), ext, number) for i in range(n)],
              extensions=[{"extension": ext, "label": "Boardroom", "department": "Facilities"}])


def test_toll_fraud_after_hours():
    [alert] = detections.toll_fraud(toll(datetime(2026, 11, 15, 1, 0)))
    assert alert["entity"] == "4471" and "Cuba" in alert["evidence"]


def test_toll_fraud_ignores_business_hours_and_domestic():
    assert detections.toll_fraud(toll(datetime(2026, 11, 10, 10, 0))) == []
    assert detections.toll_fraud(toll(datetime(2026, 11, 15, 1, 0), number="+13065550100")) == []


def test_toll_fraud_minutes_to_high_risk_countries():
    # Three long calls to a high-risk destination: below the call count, above 30 minutes.
    d = ds(cdr=[call(i, datetime(2026, 11, 15, 2) + minutes(12 * i), "4471", "+252611234", dur=660)
                for i in range(3)])
    assert len(detections.toll_fraud(d)) == 1


def sim(follow, gap_hours=0.3):
    t = datetime(2026, 11, 10, 13, 0)
    events = [cust(1, t, "CUST-1", "SIM_SWAP", "Call Centre", "agent1", "KBA")]
    events += [cust(i + 2, t + timedelta(hours=gap_hours) + minutes(i), "CUST-1", e) for i, e in enumerate(follow)]
    return ds(customer=events)


def test_sim_swap_then_reset_is_high():
    [alert] = detections.sim_swap_takeover(sim(["PASSWORD_RESET", "EMAIL_CHANGE"]))
    assert alert["severity"] == "High"


def test_sim_swap_with_port_out_is_critical():
    [alert] = detections.sim_swap_takeover(sim(["PASSWORD_RESET", "PORT_OUT_REQUEST"]))
    assert alert["severity"] == "Critical"


def test_sim_swap_reset_after_24_hours_is_quiet():
    assert detections.sim_swap_takeover(sim(["PASSWORD_RESET"], gap_hours=25)) == []


def test_alert_is_raised_at_the_next_run():
    [alert] = detections.port_scan(scan(25))
    assert alert["_detected"].minute % 5 == 0 and alert["_detected"] >= alert["_trigger"]


def test_full_dataset_finds_every_planted_attack():
    alerts = detections.run_all(load(DATA))
    by_rule = {}
    for a in alerts:
        by_rule[a["rule_id"]] = by_rule.get(a["rule_id"], 0) + 1
    assert by_rule == {"DET-01": 1, "DET-02": 1, "DET-03": 2, "DET-04": 1, "DET-05": 2, "DET-06": 1, "DET-07": 3}
    # The benign look-alikes stay quiet: the Toronto trip and the late password reset.
    assert not any(a["entity"] in ("mgagnon", "CUST-100777") for a in alerts)
