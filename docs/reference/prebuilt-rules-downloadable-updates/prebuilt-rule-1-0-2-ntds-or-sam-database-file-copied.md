---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-ntds-or-sam-database-file-copied.html
---

# NTDS or SAM Database File Copied [prebuilt-rule-1-0-2-ntds-or-sam-database-file-copied]

Identifies a copy operation of the Active Directory Domain Database (ntds.dit) or Security Account Manager (SAM) files. These files contain sensitive information including hashed domain and/or local credentials.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 33

**References**:

* [https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/](https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-3---esentutlexe-sam-copy](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.002/T1003.002.md#atomic-test-3---esentutlexe-sam-copy)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access

**Version**: 6

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1509]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1744]

```js
process where event.type in ("start", "process_started") and
  (
    (process.pe.original_file_name in ("Cmd.Exe", "PowerShell.EXE", "XCOPY.EXE") and
       process.args : ("copy", "xcopy", "Copy-Item", "move", "cp", "mv")
    ) or
    (process.pe.original_file_name : "esentutl.exe" and process.args : ("*/y*", "*/vss*", "*/d*"))
  ) and
  process.args : ("*\\ntds.dit", "*\\config\\SAM", "\\*\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\*", "*/system32/config/SAM*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: Security Account Manager
    * ID: T1003.002
    * Reference URL: [https://attack.mitre.org/techniques/T1003/002/](https://attack.mitre.org/techniques/T1003/002/)



