---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/file-staged-in-root-folder-of-recycle-bin.html
---

# File Staged in Root Folder of Recycle Bin [file-staged-in-root-folder-of-recycle-bin]

Identifies files written to the root of the Recycle Bin folder instead of subdirectories. Adversaries may place files in the root of the Recycle Bin in preparation for exfiltration or to evade defenses.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*
* logs-windows.sysmon_operational-*
* endgame-*
* winlogbeat-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Collection
* Data Source: Elastic Defend
* Rule Type: BBR
* Data Source: Elastic Endgame
* Data Source: Sysmon

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_354]

```js
file where host.os.type == "windows" and event.type == "creation" and
  file.path : "?:\\$RECYCLE.BIN\\*" and
  not file.path : "?:\\$RECYCLE.BIN\\*\\*" and
  not file.name : "desktop.ini"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data Staged
    * ID: T1074
    * Reference URL: [https://attack.mitre.org/techniques/T1074/](https://attack.mitre.org/techniques/T1074/)

* Sub-technique:

    * Name: Local Data Staging
    * ID: T1074.001
    * Reference URL: [https://attack.mitre.org/techniques/T1074/001/](https://attack.mitre.org/techniques/T1074/001/)



