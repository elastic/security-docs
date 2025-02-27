---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-uac-bypass-via-diskcleanup-scheduled-task-hijack.html
---

# UAC Bypass via DiskCleanup Scheduled Task Hijack [prebuilt-rule-8-4-2-uac-bypass-via-diskcleanup-scheduled-task-hijack]

Identifies User Account Control (UAC) bypass via hijacking DiskCleanup Scheduled Task. Attackers bypass UAC to stealthily execute code with elevated permissions.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

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
* Privilege Escalation

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3563]



## Rule query [_rule_query_4260]

```js
process where event.type == "start" and
 process.args : "/autoclean" and process.args : "/d" and
 not process.executable : ("C:\\Windows\\System32\\cleanmgr.exe",
                           "C:\\Windows\\SysWOW64\\cleanmgr.exe",
                           "C:\\Windows\\System32\\taskhostw.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Bypass User Account Control
    * ID: T1548.002
    * Reference URL: [https://attack.mitre.org/techniques/T1548/002/](https://attack.mitre.org/techniques/T1548/002/)



