---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-eggshell-backdoor-execution.html
---

# EggShell Backdoor Execution [prebuilt-rule-8-4-2-eggshell-backdoor-execution]

Identifies the execution of and EggShell Backdoor. EggShell is a known post exploitation tool for macOS and Linux.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/neoneggplant/EggShell](https://github.com/neoneggplant/EggShell)

**Tags**:

* Elastic
* Host
* Linux
* macOS
* Threat Detection
* Execution

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3795]

```js
event.category:process and event.type:(start or process_started) and process.name:espl and process.args:eyJkZWJ1ZyI6*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: Python
    * ID: T1059.006
    * Reference URL: [https://attack.mitre.org/techniques/T1059/006/](https://attack.mitre.org/techniques/T1059/006/)



