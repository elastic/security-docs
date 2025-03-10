---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/trap-signals-execution.html
---

# Trap Signals Execution [trap-signals-execution]

Identify activity related where adversaries can include a trap command which then allows programs and shells to specify commands that will be executed upon receiving interrupt signals.

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
* Tactic: Privilege Escalation
* Rule Type: BBR
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1136]

```js
process where event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started") and
process.name == "trap" and process.args : "SIG*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Trap
    * ID: T1546.005
    * Reference URL: [https://attack.mitre.org/techniques/T1546/005/](https://attack.mitre.org/techniques/T1546/005/)



