---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-potential-application-shimming-via-sdbinst.html
---

# Potential Application Shimming via Sdbinst [prebuilt-rule-8-3-3-potential-application-shimming-via-sdbinst]

The Application Shim was created to allow for backward compatibility of software as the operating system codebase changes over time. This Windows functionality has been abused by attackers to stealthily gain persistence and arbitrary code execution in legitimate Windows processes.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3188]



## Rule query [_rule_query_3731]

```js
process where event.type == "start" and process.name : "sdbinst.exe" and
  not (process.args : "-m" and process.args : "-bg") and
  not process.args : "-mm"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Application Shimming
    * ID: T1546.011
    * Reference URL: [https://attack.mitre.org/techniques/T1546/011/](https://attack.mitre.org/techniques/T1546/011/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Application Shimming
    * ID: T1546.011
    * Reference URL: [https://attack.mitre.org/techniques/T1546/011/](https://attack.mitre.org/techniques/T1546/011/)



