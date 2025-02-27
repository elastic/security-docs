---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-suspicious-hidden-child-process-of-launchd.html
---

# Suspicious Hidden Child Process of Launchd [prebuilt-rule-8-4-2-suspicious-hidden-child-process-of-launchd]

Identifies the execution of a launchd child process with a hidden file. An adversary can establish persistence by installing a new logon item, launch agent, or daemon that executes upon login.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://objective-see.com/blog/blog_0x61.html](https://objective-see.com/blog/blog_0x61.md)
* [https://www.intezer.com/blog/research/operation-electrorat-attacker-creates-fake-companies-to-drain-your-crypto-wallets/](https://www.intezer.com/blog/research/operation-electrorat-attacker-creates-fake-companies-to-drain-your-crypto-wallets/)
* [https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.md)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Persistence
* Defense Evasion

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3937]

```js
event.category:process and event.type:(start or process_started) and
 process.name:.* and process.parent.executable:/sbin/launchd
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



