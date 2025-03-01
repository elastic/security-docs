---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-suspicious-automator-workflows-execution.html
---

# Suspicious Automator Workflows Execution [prebuilt-rule-8-3-3-suspicious-automator-workflows-execution]

Identifies the execution of the Automator Workflows process followed by a network connection from it’s XPC service. Adversaries may drop a custom workflow template that hosts malicious JavaScript for Automation (JXA) code as an alternative to using osascript.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5](https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Execution

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3433]

```js
sequence by host.id with maxspan=30s
 [process where event.type in ("start", "process_started") and process.name == "automator"]
 [network where process.name:"com.apple.automator.runner"]
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



