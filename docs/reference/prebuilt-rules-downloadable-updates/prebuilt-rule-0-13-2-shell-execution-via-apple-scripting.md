---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-13-2-shell-execution-via-apple-scripting.html
---

# Shell Execution via Apple Scripting [prebuilt-rule-0-13-2-shell-execution-via-apple-scripting]

Identifies the execution of the shell process (sh) via scripting (JXA or AppleScript). Adversaries may use the doShellScript functionality in JXA or do shell script in AppleScript to execute system commands.

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

* [https://developer.apple.com/library/archive/technotes/tn2065/_index.html](https://developer.apple.com/library/archive/technotes/tn2065/_index.md)
* [https://objectivebythesea.com/v2/talks/OBTS_v2_Thomas.pdf](https://objectivebythesea.com/v2/talks/OBTS_v2_Thomas.pdf)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Execution

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1288]

```js
sequence by host.id with maxspan=5s
 [process where event.type in ("start", "process_started", "info") and process.name == "osascript"] by process.pid
 [process where event.type in ("start", "process_started") and process.name == "sh" and process.args == "-c"] by process.parent.pid
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



