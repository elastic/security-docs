---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-linux-restricted-shell-breakout-via-cpulimit-shell-evasion.html
---

# Linux Restricted Shell Breakout via cpulimit Shell Evasion [prebuilt-rule-1-0-2-linux-restricted-shell-breakout-via-cpulimit-shell-evasion]

Identifies Linux binary cpulimit abuse to break out from restricted environments by spawning an interactive system shell. The cpulimit utility is used to restrict the CPU usage of a process in cases of CPU or system load exceeding the defined threshold and the activity of spawning a shell is not a standard use of this binary by a user or system administrator. This can potentially indicate a malicious actor attempting to improve the capabilities or stability of their access.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://gtfobins.github.io/gtfobins/cpulimit/](https://gtfobins.github.io/gtfobins/cpulimit/)

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

## Rule query [_rule_query_1578]

```js
process where event.type == "start" and process.name in ("bash", "sh", "dash") and
  process.parent.name == "cpulimit" and process.parent.args == "-f" and
  process.parent.args in ("/bin/sh", "/bin/bash", "/bin/dash", "sh", "bash", "dash")
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



