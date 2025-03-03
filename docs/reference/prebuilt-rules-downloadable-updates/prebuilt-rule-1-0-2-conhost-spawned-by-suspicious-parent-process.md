---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-conhost-spawned-by-suspicious-parent-process.html
---

# Conhost Spawned By Suspicious Parent Process [prebuilt-rule-1-0-2-conhost-spawned-by-suspicious-parent-process]

Detects when the Console Window Host (conhost.exe) process is spawned by a suspicious parent process, which could be indicative of code injection.

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

* [https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-one.html](https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-one.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Execution

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1602]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1851]

```js
process where event.type in ("start", "process_started") and
  process.name : "conhost.exe" and
  process.parent.name : ("svchost.exe", "lsass.exe", "services.exe", "smss.exe", "winlogon.exe", "explorer.exe",
                         "dllhost.exe", "rundll32.exe", "regsvr32.exe", "userinit.exe", "wininit.exe", "spoolsv.exe",
                         "wermgr.exe", "csrss.exe", "ctfmon.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)



