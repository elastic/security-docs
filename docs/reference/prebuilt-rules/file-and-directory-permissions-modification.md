---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/file-and-directory-permissions-modification.html
---

# File and Directory Permissions Modification [file-and-directory-permissions-modification]

Identifies the change of permissions/ownership of files/folders through built-in Windows utilities. Threat actors may require permission modification of files/folders to change, modify or delete them.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*

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
* Tactic: Defense Evasion
* Rule Type: BBR
* Data Source: Elastic Defend

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_357]

```js
process where event.type == "start" and host.os.type == "windows" and
(
  ((process.name: "icacls.exe" or process.pe.original_file_name == "iCACLS.EXE") and process.args: ("*:F", "/reset", "/setowner", "*grant*")) or
  ((process.name: "cacls.exe" or process.pe.original_file_name == "CACLS.EXE") and process.args: ("/g", "*:f")) or
  ((process.name: "takeown.exe" or process.pe.original_file_name == "takeown.exe") and process.args: ("/F")) or
  ((process.name: "attrib.exe" or process.pe.original_file_name== "ATTRIB.EXE") and process.args: "-r")
) and not user.id : "S-1-5-18" and
not (
  process.args : ("C:\\ProgramData\\Lenovo\\*", "C:\\ProgramData\\Adobe\\*", "C:\\ProgramData\\ASUS\\ASUS*")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: File and Directory Permissions Modification
    * ID: T1222
    * Reference URL: [https://attack.mitre.org/techniques/T1222/](https://attack.mitre.org/techniques/T1222/)

* Sub-technique:

    * Name: Windows File and Directory Permissions Modification
    * ID: T1222.001
    * Reference URL: [https://attack.mitre.org/techniques/T1222/001/](https://attack.mitre.org/techniques/T1222/001/)



