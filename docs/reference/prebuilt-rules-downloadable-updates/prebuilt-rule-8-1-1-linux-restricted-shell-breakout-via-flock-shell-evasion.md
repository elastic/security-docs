---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-linux-restricted-shell-breakout-via-flock-shell-evasion.html
---

# Linux Restricted Shell Breakout via flock Shell evasion [prebuilt-rule-8-1-1-linux-restricted-shell-breakout-via-flock-shell-evasion]

Identifies Linux binary flock abuse to break out from restricted environments by spawning an interactive system shell. The flock utility allows users to manage advisory file locks in shell scripts or on the command line. The activity of spawning a shell is not a standard use of this binary by a user or system administrator. It indicates a potentially malicious actor attempting to improve the capabilities or stability of their access.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://gtfobins.github.io/gtfobins/flock/](https://gtfobins.github.io/gtfobins/flock/)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Execution
* GTFOBins

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2103]

```js
process where event.type == "start" and process.parent.name == "flock" and process.parent.args == "-u" and process.parent.args == "/" and process.parent.args in ("/bin/sh", "/bin/bash", "/bin/dash", "sh", "bash", "dash") and process.name in ("bash", "dash", "sh")
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



