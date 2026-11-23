# Investigation report: SIM swap account takeovers

| | |
|---|---|
| Incidents | INC-0002 (CUST-100417), INC-0004 (CUST-100823), INC-0007 (CUST-100296) |
| Prepared by | Corporate Security, Prairie Lynx Telecom (fictional) |
| Status as of 2026-11-20 | INC-0002 and INC-0007 closed; INC-0004 contained, call recording review open |
| Classification | Internal. Lab exercise on synthetic data: every name, account and event is made up. |

## 1. Summary

Three customer accounts were taken over in one week through SIM swaps. In each case the attacker had the customer's number moved to a new SIM, used the one-time code sent to that SIM to reset the online account password, and then changed the account's contact details. Two cases went further: a request to port the number to another carrier and an order for a new device.

Detection rule DET-07 raised an alert 18, 20 and 82 minutes after each swap. The port-out was cancelled before it completed and the device shipment was recalled, so no number was lost and no device reached the attacker. Both call-centre swaps were processed under one agent ID using knowledge-based questions only, and that agent's account can also approve swaps. This report finds a verification weakness and a separation-of-duties gap. It does not find evidence that the agent took part; the call recordings that would settle that are still being reviewed.

## 2. Evidence used

| Source | What it showed |
|---|---|
| `customer_events.csv` | Every account change, with channel, agent and verification method |
| `alerts.csv`, `incidents.csv`, `incident_updates.csv` | When each alert fired and what responders did |
| `users.csv`, `entitlements.csv`, `auth_log.csv` | The agents' permissions and sign-ins on the days in question |
| Not available in the lab | Call recordings, CRM session logs, store CCTV (listed as next steps) |

## 3. Timelines

**INC-0002, CUST-100417 (Critical)**

| Time | Event ID | What happened |
|---|---|---|
| 2026-11-10 13:42:18 | EV000374 | SIM swap by phone (Call Centre), agent skowalski, verified by knowledge-based questions (KBA) |
| 13:58:31 | EV000377 | Online password reset using a code sent to the new SIM |
| 14:00:00 | ALR-0002 | DET-07 alert, Critical (18 minutes after the swap) |
| 14:03:59 | EV000378 | Account email changed |
| 14:11 | | Fraud analyst acknowledges (11 minutes, target 15) |
| 14:20:33 | EV000386 | Port-out request to another carrier |
| 14:52 | | Contained: account locked, port-out cancelled before it completed (52 minutes) |
| 2026-11-12 10:00 | | Closed: customer verified in store with photo ID and SIM restored |

**INC-0004, CUST-100823 (Critical)**

| Time | Event ID | What happened |
|---|---|---|
| 2026-11-12 19:05:03 | EV000925 | SIM swap by phone (Call Centre), agent skowalski, KBA |
| 19:21:16 | EV000928 | Online password reset using a code sent to the new SIM |
| 19:25:00 | ALR-0004 | DET-07 alert, Critical (20 minutes after the swap) |
| 19:36:27 | EV000937 | Shipping address changed |
| 19:40:42 | EV000939 | New device ordered |
| 19:52 | | On-call fraud analyst acknowledges (27 minutes, target 15: missed) |
| 2026-11-13 00:40 | | Contained: account locked; the device had already gone to the courier and the shipment was recalled (5 h 15 min, SLA 4 h: missed) |

**INC-0007, CUST-100296 (High)**

| Time | Event ID | What happened |
|---|---|---|
| 2026-11-14 10:12:47 | EV001242 | SIM swap in a store, agent nfraser, photo ID checked |
| 11:31:06 | EV001260 | Online password reset using a code sent to the new SIM |
| 11:34:11 | EV001262 | Account email changed |
| 11:35:00 | ALR-0008 | DET-07 alert, High (82 minutes after the swap) |
| 11:58 / 12:40 | | Acknowledged (23 minutes) and contained: account locked, email change reversed |
| 2026-11-17 10:00 | | Closed: the store confirmed the ID presented did not match the customer; the store manager reported it to police |

## 4. Findings

1. **The SMS password reset is the pivot.** In all three cases the password reset came 16 to 78 minutes after the swap and used a one-time code sent to the new SIM. Once the number moves, the code proves nothing about who is resetting the password.
2. **Phone verification by knowledge-based questions was enough to move a number.** 11 of the week's 29 SIM swaps were done by phone with KBA only. Answers to those questions (date of birth, address, last payment) can often be found or bought.
3. **Both call-centre frauds were processed under one agent ID.** skowalski processed 2 SIM swaps this week, both fraudulent. Two events are too few to draw a conclusion, and the pattern also fits an attacker who called back until they reached an agent who accepted their answers.
4. **That agent can approve their own swaps.** skowalski holds both `sim_swap_perform` and `sim_swap_approve` (access review finding AR-007, rule SOD-04). Of the 3 accounts with approval rights, it is the only one that also performs swaps, so no second person had to look at these two.
5. **The agent's sign-ins look normal.** skowalski signed in from Regina office addresses on both days (2026-11-10 at 07:57 and 2026-11-12 at 07:33). The 19:05 swap on 2026-11-12 was more than 11 hours after that day's only sign-in, so the shift schedule and CRM session log should be checked.
6. **Detection worked but waits for the reset.** The rule fires on the password reset, not the swap. A swap made by phone with KBA only could start closer monitoring of that account straight away.
7. **The store case is a different method.** The swap was made in person with ID that did not match the customer: a fake or borrowed ID, not a weak verification rule.

## 5. Conclusion

The most likely explanation for the two call-centre cases is social engineering: an attacker who knew enough about each customer to pass the knowledge-based questions. Agent involvement is neither shown nor ruled out by this data. The control failures are clear either way: KBA alone can move a number, password resets trust the SMS code even right after a swap, and one agent could perform and approve swaps alone.

## 6. Recommendations

| # | Action | Owner (role) | Target |
|---|---|---|---|
| 1 | Stop SIM swaps by phone on KBA alone: require a one-time code to the current SIM, or an in-store photo ID check | Customer Care Director | 2026-12-15 |
| 2 | Block online password resets by SMS for 24 hours after a SIM swap; use email or an in-store reset instead | Digital Channels Manager | 2026-12-15 |
| 3 | Hold port-out requests and device orders for 24 hours after a SIM swap, with a call to the customer's alternate contact | Customer Care Director | 2026-12-15 |
| 4 | Remove `sim_swap_approve` from agents who perform swaps (SOD-04) | IAM Administrator | 2026-11-27 |
| 5 | Start DET-07 monitoring at the swap for phone swaps with KBA only, not at the password reset | Corporate Security | 2026-12-05 |
| 6 | Finish the call recording review for both skowalski swaps and record the outcome on INC-0004 | Corporate Security with Customer Care Manager | 2026-11-27 |
| 7 | Run a 15-minute SIM swap fraud briefing for all agents (see `security-awareness-sim-swap.md`) | Corporate Security | 2026-12-05 |

## 7. Law enforcement and evidence handling

The store case (INC-0007) has been reported to police by the store manager. If the recording review confirms the call-centre cases were fraud, Corporate Security will give police a package containing the timelines above, the event IDs, the call recordings and the customer statements. Exports are saved read-only with a SHA-256 hash recorded at the time of export, so the evidence can be shown to be unchanged.
