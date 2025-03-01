---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-potential-credential-access-via-windows-utilities.html
---

# Potential Credential Access via Windows Utilities [prebuilt-rule-1-0-2-potential-credential-access-via-windows-utilities]

Identifies the execution of known Windows utilities often abused to dump Local Security Authority Server Service (LSASS) memory or the Active Directory database (NTDS.dit) in preparation for credential access.

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

* [https://lolbas-project.github.io/](https://lolbas-project.github.io/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1508]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1743]

```js
process where event.type in ("start", "process_started") and
/* update here with any new lolbas with dump capability */
(process.pe.original_file_name == "procdump" and process.args : "-ma") or
(process.name : "ProcessDump.exe" and not process.parent.executable regex~ """C:\\Program Files( \(x86\))?\\Cisco Systems\\.*""") or
(process.pe.original_file_name == "WriteMiniDump.exe" and not process.parent.executable regex~ """C:\\Program Files( \(x86\))?\\Steam\\.*""") or
(process.pe.original_file_name == "RUNDLL32.EXE" and (process.args : "MiniDump*" or process.command_line : "*comsvcs.dll*#24*")) or
(process.pe.original_file_name == "RdrLeakDiag.exe" and process.args : "/fullmemdmp") or
(process.pe.original_file_name == "SqlDumper.exe" and process.args : "0x01100*") or
(process.pe.original_file_name == "TTTracer.exe" and process.args : "-dumpFull" and process.args : "-attach") or
(process.pe.original_file_name == "ntdsutil.exe" and process.args : "create*full*") or
(process.pe.original_file_name == "diskshadow.exe" and process.args : "/s")
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

* Sub-technique:

    * Name: NTDS
    * ID: T1003.003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/003/](https://attack.mitre.org/techniques/T1003/003/)



