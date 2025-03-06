---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-6-1-system-log-file-deletion.html
---

# System Log File Deletion [prebuilt-rule-8-6-1-system-log-file-deletion]

Identifies the deletion of sensitive Linux system logs. This may indicate an attempt to evade detection or destroy forensic evidence on a system.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.fireeye.com/blog/threat-research/2020/11/live-off-the-land-an-overview-of-unc1945.html](https://www.fireeye.com/blog/threat-research/2020/11/live-off-the-land-an-overview-of-unc1945.html)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Defense Evasion
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3742]



## Rule query [_rule_query_4567]

```js
file where event.type == "deletion" and
  file.path :
    (
    "/var/run/utmp",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/var/log/faillog",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/secure",
    "/var/log/auth.log",
    "/var/log/boot.log",
    "/var/log/kern.log"
    ) and
    not process.name : ("gzip")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)

* Sub-technique:

    * Name: Clear Linux or Mac System Logs
    * ID: T1070.002
    * Reference URL: [https://attack.mitre.org/techniques/T1070/002/](https://attack.mitre.org/techniques/T1070/002/)



