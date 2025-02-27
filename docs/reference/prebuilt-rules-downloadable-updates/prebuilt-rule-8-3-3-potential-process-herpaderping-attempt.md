---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-potential-process-herpaderping-attempt.html
---

# Potential Process Herpaderping Attempt [prebuilt-rule-8-3-3-potential-process-herpaderping-attempt]

Identifies process execution followed by a file overwrite of an executable by the same parent process. This may indicate an evasion attempt to execute malicious code in a stealthy way.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/jxy-s/herpaderping](https://github.com/jxy-s/herpaderping)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3585]

```js
sequence with maxspan=5s
   [process where event.type == "start" and not process.parent.executable :
      (
         "?:\\Windows\\SoftwareDistribution\\*.exe",
         "?:\\Program Files\\Elastic\\Agent\\data\\*.exe",
         "?:\\Program Files (x86)\\Trend Micro\\*.exe"
      )
   ] by host.id, process.executable, process.parent.entity_id
   [file where event.type == "change" and event.action == "overwrite" and file.extension == "exe"] by host.id, file.path, process.entity_id
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)



