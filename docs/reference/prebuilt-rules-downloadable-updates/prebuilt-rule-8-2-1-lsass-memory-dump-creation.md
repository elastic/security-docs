---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-lsass-memory-dump-creation.html
---

# LSASS Memory Dump Creation [prebuilt-rule-8-2-1-lsass-memory-dump-creation]

Identifies the creation of a Local Security Authority Subsystem Service (lsass.exe) default memory dump. This may indicate a credential access attempt via trusted system utilities such as Task Manager (taskmgr.exe) and SQL Dumper (sqldumper.exe) or known pentesting tools such as Dumpert and AndrewSpecial.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/outflanknl/Dumpert](https://github.com/outflanknl/Dumpert)
* [https://github.com/hoangprod/AndrewSpecial](https://github.com/hoangprod/AndrewSpecial)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access

**Version**: 11

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2076]



## Rule query [_rule_query_2366]

```js
file where file.name : ("lsass*.dmp", "dumpert.dmp", "Andrew.dmp", "SQLDmpr*.mdmp", "Coredump.dmp") and

 not (process.executable : ("?:\\Program Files\\Microsoft SQL Server\\*\\Shared\\SqlDumper.exe", "?:\\Windows\\System32\\dllhost.exe") and
      file.path : ("?:\\Program Files\\Microsoft SQL Server\\*\\Shared\\ErrorDumps\\SQLDmpr*.mdmp",
                   "?:\\*\\Reporting Services\\Logfiles\\SQLDmpr*.mdmp")) and

 not (process.executable : "?:\\WINDOWS\\system32\\WerFault.exe" and
      file.path : "?:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\CrashDumps\\lsass.exe.*.dmp")
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

    * Name: LSASS Memory
    * ID: T1003.001
    * Reference URL: [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)



