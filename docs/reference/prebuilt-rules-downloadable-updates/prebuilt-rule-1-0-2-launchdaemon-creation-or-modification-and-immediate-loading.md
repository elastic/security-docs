---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-launchdaemon-creation-or-modification-and-immediate-loading.html
---

# LaunchDaemon Creation or Modification and Immediate Loading [prebuilt-rule-1-0-2-launchdaemon-creation-or-modification-and-immediate-loading]

Indicates the creation or modification of a launch daemon, which adversaries may use to repeatedly execute malicious payloads as part of persistence.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Persistence

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1716]

```js
sequence by host.id with maxspan=1m
 [file where event.type != "deletion" and file.path in ("/System/Library/LaunchDaemons/*", "/Library/LaunchDaemons/*")]
 [process where event.type in ("start", "process_started") and process.name == "launchctl" and process.args == "load"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)



