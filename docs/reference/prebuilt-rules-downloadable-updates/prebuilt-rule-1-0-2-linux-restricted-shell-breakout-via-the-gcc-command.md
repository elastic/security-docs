---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-linux-restricted-shell-breakout-via-the-gcc-command.html
---

# Linux Restricted Shell Breakout via the gcc command [prebuilt-rule-1-0-2-linux-restricted-shell-breakout-via-the-gcc-command]

Identifies Linux binary gcc abuse to break out from restricted environments by spawning an interactive system shell.The gcc utility is a complier system for various languages and mainly used to complie C and C++ programs and the activity of spawning shell is not a standard use of this binary for a user or system administrator.It indicates a potentially malicious actor attempting to improve the capabilities or stability of their access.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://gtfobins.github.io/gtfobins/gcc/](https://gtfobins.github.io/gtfobins/gcc/)

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

## Rule query [_rule_query_1584]

```js
process where event.type == "start" and process.name in ("sh", "dash", "bash")  and
  process.parent.name == "gcc" and process.parent.args == "-wrapper" and
  process.parent.args in ("sh,-s", "bash,-s", "dash,-s", "/bin/sh,-s", "/bin/bash,-s", "/bin/dash,-s")
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



