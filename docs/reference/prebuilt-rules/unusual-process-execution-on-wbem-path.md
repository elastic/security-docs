---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-process-execution-on-wbem-path.html
---

# Unusual Process Execution on WBEM Path [unusual-process-execution-on-wbem-path]

Identifies unusual processes running from the WBEM path, uncommon outside WMI-related Windows processes.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-system.security*
* winlogbeat-*
* logs-windows.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Rule Type: BBR
* Data Source: Elastic Endgame
* Data Source: System

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1187]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.executable : ("?:\\Windows\\System32\\wbem\\*", "?:\\Windows\\SysWow64\\wbem\\*") and
  not process.name : (
    "mofcomp.exe",
    "scrcons.exe",
    "unsecapp.exe",
    "wbemtest.exe",
    "winmgmt.exe",
    "wmiadap.exe",
    "wmiapsrv.exe",
    "wmic.exe",
    "wmiprvse.exe"
  )
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



