---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/discovery-of-domain-groups.html
---

# Discovery of Domain Groups [discovery-of-domain-groups]

Identifies the execution of Linux built-in commands related to account or group enumeration. Adversaries may use account and group information to orient themselves before deciding how to act.

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

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_283]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started")
 and (
  process.name in ("ldapsearch", "dscacheutil") or (process.name == "dscl" and process.args : "*-list*")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Permission Groups Discovery
    * ID: T1069
    * Reference URL: [https://attack.mitre.org/techniques/T1069/](https://attack.mitre.org/techniques/T1069/)



