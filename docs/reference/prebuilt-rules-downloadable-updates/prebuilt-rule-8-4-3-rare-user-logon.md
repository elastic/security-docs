---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-3-rare-user-logon.html
---

# Rare User Logon [prebuilt-rule-8-4-3-rare-user-logon]

A machine learning job found an unusual user name in the authentication logs. An unusual user name is one way of detecting credentialed access by means of a new or dormant user account. An inactive user account (because the user has left the organization) that becomes active may be due to credentialed access using a compromised account password. Threat actors will sometimes also create new users as a means of persisting in a compromised web application.

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

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3597]

## Triage and analysis

## Investigating Rare User Logon

This rule uses a machine learning job to detect an unusual user name in authentication logs, which could detect new accounts created for persistence.

### Possible investigation steps

- Check if the user was newly created and if the company policies were followed.
  - Identify the user account that performed the action and whether it should perform this kind of action.
- Investigate other alerts associated with the involved users during the past 48 hours.
- Investigate any abnormal account behavior, such as command executions, file creations or modifications, and network connections.

## False positive analysis

- Accounts that are used for specific purposes — and therefore not normally active — may trigger the alert.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).
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



