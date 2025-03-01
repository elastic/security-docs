---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-outbound-scheduled-task-activity-via-powershell.html
---

# Outbound Scheduled Task Activity via PowerShell [prebuilt-rule-0-14-2-outbound-scheduled-task-activity-via-powershell]

Identifies the PowerShell process loading the Task Scheduler COM DLL followed by an outbound RPC network connection within a short time period. This may indicate lateral movement or remote discovery via scheduled tasks.

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

**References**:

* [https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/](https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Execution

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1455]

```js
sequence by host.id, process.entity_id with maxspan = 5s
 [library where dll.name : "taskschd.dll" and process.name : ("powershell.exe", "pwsh.exe")]
 [network where process.name : ("powershell.exe", "pwsh.exe") and destination.port == 135 and not destination.address in ("127.0.0.1", "::1")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Scheduled Task
    * ID: T1053.005
    * Reference URL: [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)



