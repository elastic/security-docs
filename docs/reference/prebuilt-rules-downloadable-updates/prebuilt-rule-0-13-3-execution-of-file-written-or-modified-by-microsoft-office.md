---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-13-3-execution-of-file-written-or-modified-by-microsoft-office.html
---

# Execution of File Written or Modified by Microsoft Office [prebuilt-rule-0-13-3-execution-of-file-written-or-modified-by-microsoft-office]

Identifies an executable created by a Microsoft Office application and subsequently executed. These processes are often launched via scripts inside documents or during exploitation of MS Office applications.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: high

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-120m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Execution

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1325]

```js
sequence with maxspan=2h
  [file where event.type != "deletion" and file.extension : "exe" and
     (process.name : "WINWORD.EXE" or
      process.name : "EXCEL.EXE" or
      process.name : "OUTLOOK.EXE" or
      process.name : "POWERPNT.EXE" or
      process.name : "eqnedt32.exe" or
      process.name : "fltldr.exe" or
      process.name : "MSPUB.EXE" or
      process.name : "MSACCESS.EXE")
  ] by host.id, file.path
  [process where event.type in ("start", "process_started")] by host.id, process.executable
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Phishing
    * ID: T1566
    * Reference URL: [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)

* Sub-technique:

    * Name: Spearphishing Attachment
    * ID: T1566.001
    * Reference URL: [https://attack.mitre.org/techniques/T1566/001/](https://attack.mitre.org/techniques/T1566/001/)

* Sub-technique:

    * Name: Spearphishing Link
    * ID: T1566.002
    * Reference URL: [https://attack.mitre.org/techniques/T1566/002/](https://attack.mitre.org/techniques/T1566/002/)



