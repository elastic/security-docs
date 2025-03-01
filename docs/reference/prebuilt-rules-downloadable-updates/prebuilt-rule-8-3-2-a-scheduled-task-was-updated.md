---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-a-scheduled-task-was-updated.html
---

# A scheduled task was updated [prebuilt-rule-8-3-2-a-scheduled-task-was-updated]

Indicates the update of a scheduled task using Windows event logs. Adversaries can use these to establish persistence, by changing the configuration of a legit scheduled task. Some changes such as disabling or enabling a scheduled task are common and may may generate noise.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*

**Severity**: low

**Risk score**: 21

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

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2721]

```js
iam where event.action == "scheduled-task-updated" and

 /* excluding tasks created by the computer account */
 not user.name : "*$" and
 not winlog.event_data.TaskName :
          ("\\User_Feed_Synchronization-*",
           "\\OneDrive Reporting Task-S-1-5-21*",
           "\\Hewlett-Packard\\HP Web Products Detection",
           "\\Hewlett-Packard\\HPDeviceCheck")
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



