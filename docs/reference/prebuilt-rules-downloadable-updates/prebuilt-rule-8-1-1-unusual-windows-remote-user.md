---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-unusual-windows-remote-user.html
---

# Unusual Windows Remote User [prebuilt-rule-8-1-1-unusual-windows-remote-user]

A machine learning job detected an unusual remote desktop protocol (RDP) username, which can indicate account takeover or credentialed persistence using compromised accounts. RDP attacks, such as BlueKeep, also tend to use unusual usernames.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* ML

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1705]

## Triage and analysis

## Investigating an Unusual Windows User
Detection alerts from this rule indicate activity for a rare and unusual Windows RDP (remote desktop) user. Here are some possible avenues of investigation:
- Consider the user as identified by the username field. Is the user part of a group who normally logs into Windows hosts using RDP (remote desktop protocol)? Is this logon activity part of an expected workflow for the user?
- Consider the source of the login. If the source is remote, could this be related to occasional troubleshooting or support activity by a vendor or an employee working remotely?

