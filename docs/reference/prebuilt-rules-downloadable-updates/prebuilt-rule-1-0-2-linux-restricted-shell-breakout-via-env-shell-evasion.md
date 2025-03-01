---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-linux-restricted-shell-breakout-via-env-shell-evasion.html
---

# Linux Restricted Shell Breakout via env Shell Evasion [prebuilt-rule-1-0-2-linux-restricted-shell-breakout-via-env-shell-evasion]

Identifies Linux binary env abuse to break out from restricted environments by spawning an interactive system shell.The env utility is a shell command for Unix like OS which is used to print a list of environment variables and the activity of spawning shell is not a standard use of this binary for a user or system administrator. It indicates a potentially malicious actor attempting to improve the capabilities or stability of their access

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://gtfobins.github.io/gtfobins/env/](https://gtfobins.github.io/gtfobins/env/)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Execution
* GTFOBins

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1580]

```js
process where event.type == "start" and process.name : "env" and process.args_count == 2 and process.args : ("/bin/sh", "/bin/bash", "sh", "bash")
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

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)



