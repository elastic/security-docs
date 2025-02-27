---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-3-temporarily-scheduled-task-creation.html
---

# Temporarily Scheduled Task Creation [prebuilt-rule-8-4-3-temporarily-scheduled-task-creation]

Indicates the creation and deletion of a scheduled task within a short time interval. Adversaries can use these to proxy malicious execution via the schedule service and perform clean up.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4386]

```js
sequence by winlog.computer_name, winlog.event_data.TaskName with maxspan=5m
   [iam where event.action == "scheduled-task-created" and not user.name : "*$"]
   [iam where event.action == "scheduled-task-deleted" and not user.name : "*$"]
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



