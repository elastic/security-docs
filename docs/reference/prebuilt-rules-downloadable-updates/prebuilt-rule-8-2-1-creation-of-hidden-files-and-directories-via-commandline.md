---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-creation-of-hidden-files-and-directories-via-commandline.html
---

# Creation of Hidden Files and Directories via CommandLine [prebuilt-rule-8-2-1-creation-of-hidden-files-and-directories-via-commandline]

Users can mark specific files as hidden simply by putting a "." as the first character in the file or folder name. Adversaries can use this to their advantage to hide files and folders on the system for persistence and defense evasion. This rule looks for hidden files or folders in common writable directories.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 33

**References**: None

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Defense Evasion

**Version**: 10

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2029]



## Rule query [_rule_query_2314]

```js
process where event.type in ("start", "process_started") and
  process.working_directory in ("/tmp", "/var/tmp", "/dev/shm") and
  process.args regex~ """\.[a-z0-9_\-][a-z0-9_\-\.]{1,254}""" and
  not process.name in ("ls", "find", "grep")
```

**Framework**: MITRE ATT&CKTM

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

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)



