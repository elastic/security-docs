---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-microsoft-build-engine-loading-windows-credential-libraries.html
---

# Microsoft Build Engine Loading Windows Credential Libraries [prebuilt-rule-1-0-2-microsoft-build-engine-loading-windows-credential-libraries]

An instance of the Microsoft Build Engine (MSBuild) loaded dynamically linked libraries (DLLs) responsible for Windows credential management. This technique is sometimes used for credential dumping.

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

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1745]

```js
sequence by process.entity_id
 [process where event.type == "start" and (process.name : "MSBuild.exe" or process.pe.original_file_name == "MSBuild.exe")]
 [library where dll.name : ("vaultcli.dll", "SAMLib.DLL")]
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



