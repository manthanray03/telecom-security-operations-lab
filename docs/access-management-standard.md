# Access management standard

Prairie Lynx Telecom (fictional) | Corporate Security | Lab document, written to show how a standard and its compliance checks fit together.

## Purpose and scope

This standard sets the minimum rules for user accounts and permissions on corporate systems (sign-in, VPN, CRM, billing, network devices, PBX and the identity system). It applies to employees, contractors and service accounts. Each requirement has an ID; `secops/compliance.py` checks it and reports the result against NIST CSF 2.0.

## Requirements

| ID | Requirement | How it is checked | NIST CSF 2.0 |
|---|---|---|---|
| AM-01 | Every human account belongs to a person in the HR system. Contractors are entered in HR with an end date. | Enabled human accounts with no matching HR record (CC-02) | PR.AA-01 |
| AM-02 | When someone leaves, HR notifies IT and the account is disabled within 1 business day. | Terminated employees whose account is still enabled (CC-01); sign-ins after termination (rule DET-04) | PR.AA-01 |
| AM-03 | All staff enrol in multi-factor authentication. Target: at least 95% of enabled accounts. | MFA coverage (CC-05) | PR.AA-03 |
| AM-04 | Every account with a privileged permission (`user_admin`, `audit_log_admin`, `firewall_change`, `pbx_admin`) uses MFA, with no exceptions. | Privileged accounts without MFA (CC-04) | PR.AA-03 |
| AM-05 | Accounts unused for 90 days are confirmed with the manager and disabled if not needed. | Enabled accounts with no sign-in for 90+ days (CC-06) | PR.AA-05 |
| AM-06 | No one holds both halves of a separation-of-duties pair (see `data/sod_rules.csv`). | Conflicting permission pairs (CC-07) | PR.AA-05 |
| AM-07 | Service accounts are used only by systems, never for interactive sign-in. | Interactive sign-ins by service accounts (CC-03) | PR.AA-01 |
| AM-08 | Security-relevant logs reach the SIEM continuously; a silent source is investigated within 1 hour. | Hours with no firewall events (CC-08) | DE.CM-01 |

## Incident response requirements

| ID | Requirement | How it is checked | NIST CSF 2.0 |
|---|---|---|---|
| IR-01 | Every alert is reviewed as part of an incident. | Alerts not linked to an incident (CC-09) | DE.AE-02 |
| IR-02 | Every incident has a category and severity. | Incidents missing either (CC-10) | RS.MA-03 |
| IR-03 | Incidents are acknowledged within: Critical 15 minutes, High 1 hour, Medium 4 hours, Low 24 hours. | Acknowledgement time vs target (CC-11) | RS.MA-02 |
| IR-04 | Incidents are contained within: Critical 4 hours, High 24 hours, Medium 72 hours, Low 7 days. At least 90% must meet this. | Containment time vs SLA (CC-12) | RS.MI-01 |

## Separation-of-duties pairs

| Rule | Permission A | Permission B | Why |
|---|---|---|---|
| SOD-01 | billing_adjust | billing_approve | One person could credit an account and approve their own credit |
| SOD-02 | firewall_change | change_approve | One person could change a firewall rule and approve their own change |
| SOD-03 | user_admin | audit_log_admin | One person could grant access and delete the record of it |
| SOD-04 | sim_swap_perform | sim_swap_approve | One person could move a customer's number and approve the move |

## Review cycle

Corporate Security runs the access review and compliance checks weekly, sends findings to each account's manager, and reports the results to management monthly. Exceptions need a named owner, a reason and an expiry date.
