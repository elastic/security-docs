---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/linux-system-information-discovery.html
---

# Linux System Information Discovery [linux-system-information-discovery]

Enrich process events with uname and other command lines that imply Linux system information discovery.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Rule Type: BBR
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_513]

```js
process where event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started") and (
  process.name: "uname" or (
  process.name: ("cat", "more", "less") and process.args: ("*issue*", "*version*", "*profile*", "*services*", "*cpuinfo*")
  )
)
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



