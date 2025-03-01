---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/linux-system-information-discovery-via-getconf.html
---

# Linux System Information Discovery via Getconf [linux-system-information-discovery-via-getconf]

This rule identifies Linux system information discovery via the `getconf` command. The `getconf` command is used to query system configuration variables and system limits. Adversaries may use this command to gather information about the system, such as the page size, maximum number of open files, and other system limits, to aid in further exploration and exploitation of the system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.exatrack.com/Perfctl-using-portainer-and-new-persistences/](https://blog.exatrack.com/Perfctl-using-portainer-and-new-persistences/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Rule Type: BBR
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_514]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started") and
process.name == "getconf"
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



