---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-linux-restricted-shell-breakout-via-apt-apt-get-changelog-escape.html
---

# Linux Restricted Shell Breakout via  apt/apt-get Changelog Escape [prebuilt-rule-8-1-1-linux-restricted-shell-breakout-via-apt-apt-get-changelog-escape]

Identifies Linux binary apt/apt-get abuse to breakout out of restricted shells or environments by spawning an interactive system shell. The apt utility allows us to manage installation and removal of softwares on Debian based Linux distributions and the activity of spawning shell is not a standard use of this binary for a user or system administrator. It indicates a potentially malicious actor attempting to improve the capabilities or stability of their access.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://gtfobins.github.io/gtfobins/apt/](https://gtfobins.github.io/gtfobins/apt/)
* [https://gtfobins.github.io/gtfobins/apt-get/](https://gtfobins.github.io/gtfobins/apt-get/)

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

## Rule query [_rule_query_2094]

```js
process where event.type == "start" and process.name == "sensible-pager" and
  process.args in ("/bin/sh", "/bin/bash", "/bin/dash", "sh", "bash", "dash") and
  process.parent.name in ("apt", "apt-get") and process.parent.args == "changelog"
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



