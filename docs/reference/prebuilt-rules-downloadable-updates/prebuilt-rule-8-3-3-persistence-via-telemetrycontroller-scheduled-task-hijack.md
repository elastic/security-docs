---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-persistence-via-telemetrycontroller-scheduled-task-hijack.html
---

# Persistence via TelemetryController Scheduled Task Hijack [prebuilt-rule-8-3-3-persistence-via-telemetrycontroller-scheduled-task-hijack]

Detects the successful hijack of Microsoft Compatibility Appraiser scheduled task to establish persistence with an integrity level of system.

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

* [https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence/?utm_content=131234033&utm_medium=social&utm_source=twitter&hss_channel=tw-403811306](https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence/?utm_content=131234033&utm_medium=social&utm_source=twitter&hss_channel=tw-403811306)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3192]



## Rule query [_rule_query_3735]

```js
process where event.type == "start" and
  process.parent.name : "CompatTelRunner.exe" and process.args : "-cv*" and
  not process.name : ("conhost.exe",
                      "DeviceCensus.exe",
                      "CompatTelRunner.exe",
                      "DismHost.exe",
                      "rundll32.exe",
                      "powershell.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Scheduled Task
    * ID: T1053.005
    * Reference URL: [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)



