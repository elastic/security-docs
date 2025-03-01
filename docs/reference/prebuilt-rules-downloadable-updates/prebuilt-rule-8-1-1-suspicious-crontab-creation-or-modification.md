---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-suspicious-crontab-creation-or-modification.html
---

# Suspicious CronTab Creation or Modification [prebuilt-rule-8-1-1-suspicious-crontab-creation-or-modification]

Identifies attempts to create or modify a crontab via a process that is not crontab (i.e python, osascript, etc.). This activity should not be highly prevalent and could indicate the use of cron as a persistence mechanism by a threat actor.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
* [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Persistence

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1956]

```js
file where event.type != "deletion" and process.name != null and
  file.path : "/private/var/at/tabs/*" and not process.executable == "/usr/bin/crontab"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Cron
    * ID: T1053.003
    * Reference URL: [https://attack.mitre.org/techniques/T1053/003/](https://attack.mitre.org/techniques/T1053/003/)



