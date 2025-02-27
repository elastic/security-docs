---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-creation-of-hidden-launch-agent-or-daemon.html
---

# Creation of Hidden Launch Agent or Daemon [prebuilt-rule-8-2-1-creation-of-hidden-launch-agent-or-daemon]

Identifies the creation of a hidden launch agent or daemon. An adversary may establish persistence by installing a new launch agent or daemon which executes at login.

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

* [https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.md)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Persistence
* Defense Evasion

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2048]



## Rule query [_rule_query_2338]

```js
file where event.type != "deletion" and
  file.path :
  (
    "/System/Library/LaunchAgents/.*.plist",
    "/Library/LaunchAgents/.*.plist",
    "/Users/*/Library/LaunchAgents/.*.plist",
    "/System/Library/LaunchDaemons/.*.plist",
    "/Library/LaunchDaemons/.*.plist"
  )
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

* Sub-technique:

    * Name: Launch Agent
    * ID: T1543.001
    * Reference URL: [https://attack.mitre.org/techniques/T1543/001/](https://attack.mitre.org/techniques/T1543/001/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hide Artifacts
    * ID: T1564
    * Reference URL: [https://attack.mitre.org/techniques/T1564/](https://attack.mitre.org/techniques/T1564/)

* Sub-technique:

    * Name: Hidden Files and Directories
    * ID: T1564.001
    * Reference URL: [https://attack.mitre.org/techniques/T1564/001/](https://attack.mitre.org/techniques/T1564/001/)



