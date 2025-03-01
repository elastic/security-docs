---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-execution-via-electron-child-process-node-js-module.html
---

# Execution via Electron Child Process Node.js Module [prebuilt-rule-8-3-3-execution-via-electron-child-process-node-js-module]

Identifies attempts to execute a child process from within the context of an Electron application using the child_process Node.js module. Adversaries may abuse this technique to inherit permissions from parent processes.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.matthewslipper.com/2019/09/22/everything-you-wanted-electron-child-process.html](https://www.matthewslipper.com/2019/09/22/everything-you-wanted-electron-child-process.md)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/)
* [https://nodejs.org/api/child_process.html](https://nodejs.org/api/child_process.md)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Defense Evasion
* Execution

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3430]

```js
event.category:process and event.type:(start or process_started) and process.args:("-e" and const*require*child_process*)
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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)



