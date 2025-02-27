---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-suspicious-endpoint-security-parent-process.html
---

# Suspicious Endpoint Security Parent Process [prebuilt-rule-8-4-1-suspicious-endpoint-security-parent-process]

A suspicious Endpoint Security parent process was detected. This may indicate a process hollowing or other form of code injection.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion
* Elastic Endgame

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2742]



## Rule query [_rule_query_3136]

```js
process where event.type == "start" and
 process.name : ("esensor.exe", "elastic-endpoint.exe") and
 process.parent.executable != null and
  /* add FPs here */
 not process.parent.executable : ("C:\\Program Files\\Elastic\\*",
                                  "C:\\Windows\\System32\\services.exe",
                                  "C:\\Windows\\System32\\WerFault*.exe",
                                  "C:\\Windows\\System32\\wermgr.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)



