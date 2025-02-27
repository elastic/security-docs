---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-suspicious-image-load-taskschd-dll-from-ms-office.html
---

# Suspicious Image Load (taskschd.dll) from MS Office [prebuilt-rule-1-0-2-suspicious-image-load-taskschd-dll-from-ms-office]

Identifies a suspicious image load (taskschd.dll) from Microsoft Office processes. This behavior may indicate adversarial activity where a scheduled task is configured via Windows Component Object Model (COM). This technique can be used to configure persistence and evade monitoring by avoiding the usage of the traditional Windows binary (schtasks.exe) used to manage scheduled tasks.

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

**References**:

* [https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16](https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16)
* [https://www.clearskysec.com/wp-content/uploads/2020/10/Operation-Quicksand.pdf](https://www.clearskysec.com/wp-content/uploads/2020/10/Operation-Quicksand.pdf)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1644]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1904]

```js
library where process.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "MSPUB.EXE", "MSACCESS.EXE") and
  event.action : "load" and
  event.category : "library" and
  dll.name : "taskschd.dll"
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



