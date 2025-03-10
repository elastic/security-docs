---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/system-network-connections-discovery.html
---

# System Network Connections Discovery [system-network-connections-discovery]

Adversaries may attempt to get a listing of network connections to or from a compromised system.

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
* OS: macOS
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

## Rule query [_rule_query_1112]

```js
process where event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started") and
process.name in ("netstat", "lsof", "who", "w")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Network Connections Discovery
    * ID: T1049
    * Reference URL: [https://attack.mitre.org/techniques/T1049/](https://attack.mitre.org/techniques/T1049/)



