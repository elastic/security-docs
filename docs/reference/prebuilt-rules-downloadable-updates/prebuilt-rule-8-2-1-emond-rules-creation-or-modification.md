---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-emond-rules-creation-or-modification.html
---

# Emond Rules Creation or Modification [prebuilt-rule-8-2-1-emond-rules-creation-or-modification]

Identifies the creation or modification of the Event Monitor Daemon (emond) rules. Adversaries may abuse this service by writing a rule to execute commands when a defined event occurs, such as system start up or user authentication.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.xorrior.com/emond-persistence/](https://www.xorrior.com/emond-persistence/)
* [https://www.sentinelone.com/blog/how-malware-persists-on-macos/](https://www.sentinelone.com/blog/how-malware-persists-on-macos/)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Persistence

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2047]



## Rule query [_rule_query_2337]

```js
file where event.type != "deletion" and
 file.path : ("/private/etc/emond.d/rules/*.plist", "/etc/emon.d/rules/*.plist", "/private/var/db/emondClients/*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Emond
    * ID: T1546.014
    * Reference URL: [https://attack.mitre.org/techniques/T1546/014/](https://attack.mitre.org/techniques/T1546/014/)



