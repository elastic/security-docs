---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-unusual-source-ip-for-a-user-to-logon-from.html
---

# Unusual Source IP for a User to Logon from [prebuilt-rule-8-2-1-unusual-source-ip-for-a-user-to-logon-from]

A machine learning job detected a user logging in from an IP address that is unusual for the user. This can be due to credentialed access via a compromised account when the user and the threat actor are in different locations. An unusual source IP address for a username could also be due to lateral movement when a compromised account is used to pivot between hosts.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/reference/security/prebuilt-jobs.md](/reference/prebuilt-jobs.md)

**Tags**:

* Elastic
* Authentication
* Threat Detection
* ML
* Initial Access

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)


