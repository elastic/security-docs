---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-linux-restricted-shell-breakout-via-busybox-shell-evasion.html
---

# Linux Restricted Shell Breakout via busybox Shell Evasion [prebuilt-rule-1-0-2-linux-restricted-shell-breakout-via-busybox-shell-evasion]

Identifies Linux binary busybox abuse to break out from restricted environments by spawning an interactive system shell.The busybox is software utility suite that provides several Unix utilities in a single executable file and the activity of spawing a shell is not a standard use of this binary by a user or system administrator. It indicates a potentially malicious actor attempting to improve the capabilities or stability of their access.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://gtfobins.github.io/gtfobins/busybox/](https://gtfobins.github.io/gtfobins/busybox/)

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

## Rule query [_rule_query_1576]

```js
process where event.type == "start" and process.name == "busybox" and process.args_count == 2 and process.args in ("/bin/sh", "/bin/ash", "sh", "ash")
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



