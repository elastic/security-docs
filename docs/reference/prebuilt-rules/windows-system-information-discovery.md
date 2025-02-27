---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/windows-system-information-discovery.html
---

# Windows System Information Discovery [windows-system-information-discovery]

Detects the execution of commands used to discover information about the system, which attackers may use after compromising a system to gain situational awareness.

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
* Rule Type: BBR
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: System

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1238]

```js
process where host.os.type == "windows" and event.type == "start" and
(
  (
    process.name : "cmd.exe" and process.args : "ver*" and not
    process.parent.executable : (
        "?:\\Users\\*\\AppData\\Local\\Keybase\\upd.exe",
        "?:\\Users\\*\\python*.exe"
    )
  ) or
  process.name : ("systeminfo.exe", "hostname.exe") or
  (process.name : "wmic.exe" and process.args : "os" and process.args : "get")
) and not
process.parent.executable : (
    "?:\\Program Files\\*",
    "?:\\Program Files (x86)\\*",
    "?:\\ProgramData\\*"
) and not user.id : "S-1-5-18"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)



