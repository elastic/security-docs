---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-13-2-potential-printnightmare-file-modification.html
---

# Potential PrintNightmare File Modification [prebuilt-rule-0-13-2-potential-printnightmare-file-modification]

Detects the creation or modification of a print driver with an unusual file name. This may indicate attempts to exploit privilege escalation vulnerabilities related to the Print Spooler service. For more information refer to CVE-2021-34527 and verify that the impacted system is investigated.

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

* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)
* [https://github.com/afwu/PrintNightmare](https://github.com/afwu/PrintNightmare)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1283]

```js
/* This rule is compatible with both Sysmon and Elastic Endpoint */

file where process.name : "spoolsv.exe" and
 file.name : ("kernelbase.dll", "ntdll.dll", "kernel32.dll", "winhttp.dll", "user32.dll") and
 file.path : "?:\\Windows\\System32\\spool\\drivers\\x64\\3\\*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)



