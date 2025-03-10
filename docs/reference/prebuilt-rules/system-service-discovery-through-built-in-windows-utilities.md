---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/system-service-discovery-through-built-in-windows-utilities.html
---

# System Service Discovery through built-in Windows Utilities [system-service-discovery-through-built-in-windows-utilities]

Detects the usage of commonly used system service discovery techniques, which attackers may use during the reconnaissance phase after compromising a system in order to gain a better understanding of the environment and/or escalate privileges.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.*
* endgame-*
* logs-system.security*

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
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Rule Type: BBR
* Data Source: System

**Version**: 109

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1114]

```js
process where host.os.type == "windows" and event.type == "start" and
  (
  ((process.name: "net.exe" or process.pe.original_file_name == "net.exe" or (process.name : "net1.exe" and
    not process.parent.name : "net.exe")) and process.args : ("start", "use") and process.args_count == 2) or
  ((process.name: "sc.exe" or process.pe.original_file_name == "sc.exe") and process.args: ("query", "q*")) or
  ((process.name: "tasklist.exe" or process.pe.original_file_name == "tasklist.exe") and process.args: "/svc") or
  (process.name : "psservice.exe" or process.pe.original_file_name == "psservice.exe")
  ) and not user.id : "S-1-5-18"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Service Discovery
    * ID: T1007
    * Reference URL: [https://attack.mitre.org/techniques/T1007/](https://attack.mitre.org/techniques/T1007/)



