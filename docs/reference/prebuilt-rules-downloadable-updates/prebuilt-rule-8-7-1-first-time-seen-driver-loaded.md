---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-first-time-seen-driver-loaded.html
---

# First Time Seen Driver Loaded [prebuilt-rule-8-7-1-first-time-seen-driver-loaded]

Identifies the load of a driver with an original file name and signature values that were observed for the first time during the last 30 days. This rule type can help baseline drivers installation within your environment.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/kr/security-labs/stopping-vulnerable-driver-attacks](https://www.elastic.co/kr/security-labs/stopping-vulnerable-driver-attacks)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4677]

```js
event.category : "driver" and event.action : "load"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Windows Service
    * ID: T1543.003
    * Reference URL: [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)



