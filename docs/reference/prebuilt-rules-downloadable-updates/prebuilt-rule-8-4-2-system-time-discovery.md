---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-system-time-discovery.html
---

# System Time Discovery [prebuilt-rule-8-4-2-system-time-discovery]

Detects the usage of commonly used system time discovery techniques, which attackers may use during the reconnaissance phase after compromising a system.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

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
* Discovery
* Elastic Endgame

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3782]

```js
process where event.type == "start" and
(
 ((process.name: "net.exe" or (process.name : "net1.exe" and not process.parent.name : "net.exe")) and process.args : "time") or
 (process.name: "w32tm.exe" and process.args: "/tz") or
 (process.name: "tzutil.exe" and process.args: "/g")
)
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



