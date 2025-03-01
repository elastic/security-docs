---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-creation-of-a-hidden-local-user-account.html
---

# Creation of a Hidden Local User Account [prebuilt-rule-8-2-1-creation-of-a-hidden-local-user-account]

Identifies the creation of a hidden local user account by appending the dollar sign to the account name. This is sometimes done by attackers to increase access to a system and avoid appearing in the results of accounts listing using the net users command.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://web.archive.org/web/20230329153858/https://blog.menasec.net/2019/02/threat-hunting-6-hiding-in-plain-sights_8.html](https://web.archive.org/web/20230329153858/https://blog.menasec.net/2019/02/threat-hunting-6-hiding-in-plain-sights_8.md)
* [https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/tree/master/2020/2020.12.15.Lazarus_Campaign](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/tree/master/2020/2020.12.15.Lazarus_Campaign)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2206]

## Triage and analysis

## Investigating Creation of a Hidden Local User Account

Attackers can create accounts ending with a `$` symbol to make the account hidden to user enumeration utilities and
bypass detections that identify computer accounts by this pattern to apply filters.

This rule uses registry events to identify the creation of local hidden accounts.

### Possible investigation steps

- Identify the user account that performed the action and whether it should perform this kind of action.
- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for
prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.

## False positive analysis

- This activity is unlikely to happen legitimately. Benign true positive (B-TPs) can be added as exceptions if necessary.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Delete the hidden account.
- Review the privileges assigned to the involved users to ensure that the least privilege principle is being followed.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2496]

```js
registry where registry.path : "HKLM\\SAM\\SAM\\Domains\\Account\\Users\\Names\\*$\\"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create Account
    * ID: T1136
    * Reference URL: [https://attack.mitre.org/techniques/T1136/](https://attack.mitre.org/techniques/T1136/)

* Sub-technique:

    * Name: Local Account
    * ID: T1136.001
    * Reference URL: [https://attack.mitre.org/techniques/T1136/001/](https://attack.mitre.org/techniques/T1136/001/)



