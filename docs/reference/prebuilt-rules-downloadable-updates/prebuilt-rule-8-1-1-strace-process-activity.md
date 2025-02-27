---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-strace-process-activity.html
---

# Strace Process Activity [prebuilt-rule-8-1-1-strace-process-activity]

Strace is a useful diagnostic, instructional, and debugging tool. This rule identifies a privileged context execution of strace which can be used to escape restrictive environments by instantiating a shell in order to elevate privileges or move laterally.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://en.wikipedia.org/wiki/Strace](https://en.wikipedia.org/wiki/Strace)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Privilege Escalation

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1974]

```js
event.category:process and event.type:(start or process_started) and process.name:strace
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)



