-- Queries behind the dashboard and the management summary.
-- Each query starts with a "-- name:" line.

-- name: alerts_by_rule
SELECT a.rule_id, a.rule_name, a.technique, COUNT(*) AS alerts, MAX(r.rank) AS worst_rank
FROM alerts a JOIN severity_rank r ON r.severity = a.severity
GROUP BY a.rule_id, a.rule_name, a.technique
ORDER BY a.rule_id;

-- name: incidents_by_severity
SELECT i.severity, COUNT(*) AS incidents,
       SUM(CASE WHEN status <> 'Closed' THEN 1 ELSE 0 END) AS not_closed
FROM incidents i JOIN severity_rank r ON r.severity = i.severity
GROUP BY i.severity
ORDER BY MAX(r.rank) DESC;

-- name: incidents_by_status
SELECT status, COUNT(*) AS incidents
FROM incidents
GROUP BY status
ORDER BY CASE status WHEN 'Open' THEN 1 WHEN 'Acknowledged' THEN 2 WHEN 'Contained' THEN 3 ELSE 4 END;

-- name: response_targets
SELECT COUNT(*) AS incidents,
       SUM(CASE WHEN ack_met = 'Yes' THEN 1 ELSE 0 END) AS ack_met,
       SUM(CASE WHEN contain_met = 'Yes' THEN 1 ELSE 0 END) AS contain_met,
       SUM(CASE WHEN contain_met = 'Overdue' THEN 1 ELSE 0 END) AS overdue
FROM incidents;

-- name: response_times
-- Minutes, for the median calculation in Python (SQLite has no MEDIAN).
SELECT minutes_to_detect, minutes_to_ack, minutes_to_contain
FROM incidents;

-- name: needs_attention
-- Not closed, worst first: what management should ask about this week.
SELECT i.incident_id, i.title, i.severity, i.status, i.opened_at, i.contain_due, i.contain_met
FROM incidents i JOIN severity_rank r ON r.severity = i.severity
WHERE i.status <> 'Closed'
ORDER BY CASE i.contain_met WHEN 'Overdue' THEN 0 ELSE 1 END, r.rank DESC, i.opened_at;

-- name: findings_by_check
SELECT f.check_name, f.requirement, f.severity, COUNT(*) AS accounts
FROM findings f JOIN severity_rank r ON r.severity = f.severity
GROUP BY f.check_name, f.requirement, f.severity
ORDER BY MAX(r.rank) DESC, accounts DESC, check_name;

-- name: findings_by_department
SELECT department, COUNT(*) AS findings
FROM findings
GROUP BY department
ORDER BY findings DESC, department;

-- name: compliance_score
SELECT COUNT(*) AS checks,
       SUM(CASE WHEN result = 'Pass' THEN 1 ELSE 0 END) AS passed
FROM compliance;
