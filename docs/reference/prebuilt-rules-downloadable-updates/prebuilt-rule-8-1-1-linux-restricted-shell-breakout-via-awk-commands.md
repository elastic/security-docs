---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-linux-restricted-shell-breakout-via-awk-commands.html
---

# Linux Restricted Shell Breakout via awk Commands [prebuilt-rule-8-1-1-linux-restricted-shell-breakout-via-awk-commands]

Identifies Linux binary awk abuse to breakout out of restricted shells or environments by spawning an interactive system shell. The awk utility is a text processing language used for data extraction and reporting tools and the activity of spawning shell is not a standard use of this binary for a user or system administrator. It indicates a potentially malicious actor attempting to improve the capabilities or stability of their access.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://gtfobins.github.io/gtfobins/nawk/](https://gtfobins.github.io/gtfobins/nawk/)
* [https://gtfobins.github.io/gtfobins/mawk/](https://gtfobins.github.io/gtfobins/mawk/)

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

## Rule query [_rule_query_2095]

```js
process where event.type == "start" and process.name in ("sh", "bash", "dash") and
  process.parent.name in ("nawk", "mawk", "awk", "gawk") and process.parent.args : "BEGIN {system(*)}"
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



