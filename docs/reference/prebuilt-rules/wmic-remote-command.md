---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/wmic-remote-command.html
---

# WMIC Remote Command [wmic-remote-command]

Identifies the use of wmic.exe to run commands on remote hosts. While this can be used by administrators legitimately, attackers can abuse this built-in utility to achieve lateral movement.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* winlogbeat-*

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
* Tactic: Lateral Movement
* Data Source: Elastic Defend
* Rule Type: BBR
* Data Source: Sysmon
* Data Source: Elastic Endgame
* Data Source: System

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1212]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.name : "WMIC.exe" and
  process.args : "*node:*" and
  process.args : ("call", "set", "get") and
  not process.args : ("*/node:localhost*", "*/node:\"127.0.0.1\"*", "/node:127.0.0.1")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: Windows Remote Management
    * ID: T1021.006
    * Reference URL: [https://attack.mitre.org/techniques/T1021/006/](https://attack.mitre.org/techniques/T1021/006/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Windows Management Instrumentation
    * ID: T1047
    * Reference URL: [https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/)



