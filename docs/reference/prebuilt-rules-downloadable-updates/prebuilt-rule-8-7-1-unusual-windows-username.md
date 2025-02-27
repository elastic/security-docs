---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-unusual-windows-username.html
---

# Unusual Windows Username [prebuilt-rule-8-7-1-unusual-windows-username]

A machine learning job detected activity for a username that is not normally active, which can indicate unauthorized changes, activity by unauthorized users, lateral movement, or compromised credentials. In many organizations, new usernames are not often created apart from specific types of system activities, such as creating new accounts for new employees. These user accounts quickly become active and routine. Events from rarely used usernames can point to suspicious activity. Additionally, automated Linux fleets tend to see activity from rarely used usernames only when personnel log in to make authorized or unauthorized changes, or threat actors have acquired credentials and log in for malicious purposes. Unusual usernames can also indicate pivoting, where compromised credentials are used to try and move laterally from one host to another.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/reference/security/prebuilt-jobs.md](/reference/prebuilt-jobs.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* ML
* Initial Access

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3833]

## Triage and analysis

## Investigating an Unusual Windows User
Detection alerts from this rule indicate activity for a Windows user name that is rare and unusual. Here are some possible avenues of investigation:
- Consider the user as identified by the username field. Is this program part of an expected workflow for the user who ran this program on this host? Could this be related to occasional troubleshooting or support activity?
- Examine the history of user activity. If this user only manifested recently, it might be a service account for a new software package. If it has a consistent cadence (for example if it runs monthly or quarterly), it might be part of a monthly or quarterly business process.
- Examine the process arguments, title and working directory. These may provide indications as to the source of the program or the nature of the tasks that the user is performing.
- Consider the same for the parent process. If the parent process is a legitimate system utility or service, this could be related to software updates or system management. If the parent process is something user-facing like an Office application, this process could be more suspicious.
**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Domain Accounts
    * ID: T1078.002
    * Reference URL: [https://attack.mitre.org/techniques/T1078/002/](https://attack.mitre.org/techniques/T1078/002/)

* Sub-technique:

    * Name: Local Accounts
    * ID: T1078.003
    * Reference URL: [https://attack.mitre.org/techniques/T1078/003/](https://attack.mitre.org/techniques/T1078/003/)



