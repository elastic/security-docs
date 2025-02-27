---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-linux-restricted-shell-breakout-via-the-find-command.html
---

# Linux Restricted Shell Breakout via the find command [prebuilt-rule-1-0-2-linux-restricted-shell-breakout-via-the-find-command]

Identifies Linux binary find abuse to break out from restricted environments by spawning an interactive system shell. The find command in Unix is a command line utility for walking a file hirerarchy and the activity of spawning shell is not a standard use of this binary for a user or system administrator.It indicates a potentially malicious actor attempting to improve the capabilities or stability of their access.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://gtfobins.github.io/gtfobins/find/](https://gtfobins.github.io/gtfobins/find/)

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

## Rule query [_rule_query_1582]

```js
process where event.type == "start" and process.name in ("bash", "sh") and
  process.parent.name == "find" and process.parent.args == "-exec" and
  process.parent.args == ";" and process.parent.args in ("/bin/bash", "/bin/sh", "bash", "sh")
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



