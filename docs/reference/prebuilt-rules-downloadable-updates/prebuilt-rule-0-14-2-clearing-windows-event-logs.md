---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-clearing-windows-event-logs.html
---

# Clearing Windows Event Logs [prebuilt-rule-0-14-2-clearing-windows-event-logs]

Identifies attempts to clear or disable Windows event log stores using Windows wevetutil command. This is often done by attackers in an attempt to evade detection or destroy forensic evidence on a system.

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
* Defense Evasion

**Version**: 10

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1426]

```js
process where event.type in ("process_started", "start") and
  (process.name : "wevtutil.exe" or process.pe.original_file_name == "wevtutil.exe") and
    process.args : ("/e:false", "cl", "clear-log") or
  process.name : "powershell.exe" and process.args : "Clear-EventLog"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal on Host
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)

* Sub-technique:

    * Name: Clear Windows Event Logs
    * ID: T1070.001
    * Reference URL: [https://attack.mitre.org/techniques/T1070/001/](https://attack.mitre.org/techniques/T1070/001/)



