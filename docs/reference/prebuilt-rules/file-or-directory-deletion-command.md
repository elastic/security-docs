---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/file-or-directory-deletion-command.html
---

# File or Directory Deletion Command [file-or-directory-deletion-command]

This rule identifies the execution of commands that can be used to delete files and directories. Adversaries may delete files and directories on a host system, such as logs, browser history, or malware.

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

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_359]

```js
process where host.os.type == "windows" and event.type == "start" and
(
  (process.name: "rundll32.exe" and process.args: "*InetCpl.cpl,Clear*") or
  (process.name: "reg.exe" and process.args:"delete") or
  (
    process.name: "cmd.exe" and process.args: ("*rmdir*", "*rm *", "rm") and
    not process.args : (
          "*\\AppData\\Local\\Microsoft\\OneDrive\\*",
          "*\\AppData\\Local\\Temp\\DockerDesktop\\*",
          "*\\AppData\\Local\\Temp\\Report.*",
          "*\\AppData\\Local\\Temp\\*.PackageExtraction"
    )
  ) or
  (process.name: "powershell.exe" and process.args: ("*rmdir", "rm", "rd", "*Remove-Item*", "del", "*]::Delete(*"))
) and not user.id : "S-1-5-18"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)

* Sub-technique:

    * Name: File Deletion
    * ID: T1070.004
    * Reference URL: [https://attack.mitre.org/techniques/T1070/004/](https://attack.mitre.org/techniques/T1070/004/)



