---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-potential-persistence-via-periodic-tasks.html
---

# Potential Persistence via Periodic Tasks [prebuilt-rule-8-3-3-potential-persistence-via-periodic-tasks]

Identifies the creation or modification of the default configuration for periodic tasks. Adversaries may abuse periodic tasks to execute malicious code or maintain persistence.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://opensource.apple.com/source/crontabs/crontabs-13/private/etc/defaults/periodic.conf.auto.html](https://opensource.apple.com/source/crontabs/crontabs-13/private/etc/defaults/periodic.conf.auto.md)
* [https://www.oreilly.com/library/view/mac-os-x/0596003706/re328.html](https://www.oreilly.com/library/view/mac-os-x/0596003706/re328.md)
* [https://github.com/D00MFist/PersistentJXA/blob/master/PeriodicPersist.js](https://github.com/D00MFist/PersistentJXA/blob/master/PeriodicPersist.js)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Persistence

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3459]

```js
event.category:"file" and not event.type:"deletion" and
 file.path:(/private/etc/periodic/* or /private/etc/defaults/periodic.conf or /private/etc/periodic.conf)
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



