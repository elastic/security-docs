---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/process-discovery-using-built-in-tools.html
---

# Process Discovery Using Built-in Tools [process-discovery-using-built-in-tools]

This rule identifies the execution of commands that can be used to enumerate running processes. Adversaries may enumerate processes to identify installed applications and security solutions.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-system.security*
* winlogbeat-*
* logs-windows.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Discovery
* Rule Type: BBR
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: System

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_888]

```js
process where host.os.type == "windows" and event.type == "start" and process.args != null and
  (
    process.name :("PsList.exe", "qprocess.exe") or
   (process.name : "powershell.exe" and process.args : ("*get-process*", "*Win32_Process*")) or
   (process.name : "wmic.exe" and process.args : ("process", "*Win32_Process*")) or
   (process.name : "tasklist.exe" and not process.args : ("pid eq*")) or
   (process.name : "query.exe" and process.args : "process")
  ) and not user.id : "S-1-5-18"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Process Discovery
    * ID: T1057
    * Reference URL: [https://attack.mitre.org/techniques/T1057/](https://attack.mitre.org/techniques/T1057/)



