---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-linux-restricted-shell-breakout-via-the-ssh-command.html
---

# Linux Restricted Shell Breakout via the SSH command [prebuilt-rule-1-0-2-linux-restricted-shell-breakout-via-the-ssh-command]

Identifies Linux binary SSH abuse to break out from restricted environments by spawning an interactive system shell. SSH is a network protocol that gives users, particularly system administrators, a secure way to access a computer over a network. The activity of spawning shell is not a standard use of this binary for a user or system administrator. It indicates a potentially malicious actor attempting to improve the capabilities or stability of their access.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://gtfobins.github.io/gtfobins/ssh/](https://gtfobins.github.io/gtfobins/ssh/)

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

## Rule query [_rule_query_1586]

```js
process where event.type == "start" and process.name : ("bash", "sh", "dash") and
  process.parent.name == "ssh" and process.parent.args == "-o" and
  process.parent.args in ("ProxyCommand=;sh 0<&2 1>&2", "ProxyCommand=;bash 0<&2 1>&2", "ProxyCommand=;dash 0<&2 1>&2", "ProxyCommand=;/bin/sh 0<&2 1>&2", "ProxyCommand=;/bin/bash 0<&2 1>&2", "ProxyCommand=;/bin/dash 0<&2 1>&2")
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



