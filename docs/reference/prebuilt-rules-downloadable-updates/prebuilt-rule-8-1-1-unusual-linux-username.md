---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-unusual-linux-username.html
---

# Unusual Linux Username [prebuilt-rule-8-1-1-unusual-linux-username]

A machine learning job detected activity for a username that is not normally active, which can indicate unauthorized changes, activity by unauthorized users, lateral movement, or compromised credentials. In many organizations, new usernames are not often created apart from specific types of system activities, such as creating new accounts for new employees. These user accounts quickly become active and routine. Events from rarely used usernames can point to suspicious activity. Additionally, automated Linux fleets tend to see activity from rarely used usernames only when personnel log in to make authorized or unauthorized changes, or threat actors have acquired credentials and log in for malicious purposes. Unusual usernames can also indicate pivoting, where compromised credentials are used to try and move laterally from one host to another.

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
* Linux
* Threat Detection
* ML

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1699]

## Triage and analysis

## Investigating an Unusual Linux User
Detection alerts from this rule indicate activity for a Linux user name that is rare and unusual. Here are some possible avenues of investigation:
- Consider the user as identified by the username field. Is this program part of an expected workflow for the user who ran this program on this host? Could this be related to troubleshooting or debugging activity by a developer or site reliability engineer?
- Examine the history of user activity. If this user only manifested recently, it might be a service account for a new software package. If it has a consistent cadence (for example if it runs monthly or quarterly), it might be part of a monthly or quarterly business process.
- Examine the process arguments, title and working directory. These may provide indications as to the source of the program or the nature of the tasks that the user is performing.

