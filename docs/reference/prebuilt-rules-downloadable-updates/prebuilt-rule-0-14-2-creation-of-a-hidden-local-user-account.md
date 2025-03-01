---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-creation-of-a-hidden-local-user-account.html
---

# Creation of a Hidden Local User Account [prebuilt-rule-0-14-2-creation-of-a-hidden-local-user-account]

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

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1471]

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



