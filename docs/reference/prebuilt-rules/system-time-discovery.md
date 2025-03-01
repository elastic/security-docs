---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/system-time-discovery.html
---

# System Time Discovery [system-time-discovery]

Detects the usage of commonly used system time discovery techniques, which attackers may use during the reconnaissance phase after compromising a system.

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

**Version**: 110

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1116]

```js
process where host.os.type == "windows" and event.type == "start" and
(
 (
    (process.name: "net.exe" or (process.name : "net1.exe" and not process.parent.name : "net.exe")) and
    process.args : "time" and not process.args : "/set"
 ) or
 (process.name: "w32tm.exe" and process.args: "/tz") or
 (process.name: "tzutil.exe" and process.args: "/g")
) and not user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Time Discovery
    * ID: T1124
    * Reference URL: [https://attack.mitre.org/techniques/T1124/](https://attack.mitre.org/techniques/T1124/)



