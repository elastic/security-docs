---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-execution-via-msiexec.html
---

# Suspicious Execution via MSIEXEC [suspicious-execution-via-msiexec]

Identifies suspicious execution of the built-in Windows Installer, msiexec.exe, to install a package from usual paths or parent process. Adversaries may abuse msiexec.exe to launch malicious local MSI files.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* winlogbeat-*
* logs-windows.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://lolbas-project.github.io/lolbas/Binaries/Msiexec/](https://lolbas-project.github.io/lolbas/Binaries/Msiexec/)
* [https://www.guardicore.com/labs/purple-fox-rootkit-now-propagates-as-a-worm/](https://www.guardicore.com/labs/purple-fox-rootkit-now-propagates-as-a-worm/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Rule Type: BBR
* Data Source: Elastic Defend
* Data Source: Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1033]

```js
process where host.os.type == "windows" and event.action == "start" and
  process.name : "msiexec.exe" and user.id : ("S-1-5-21*", "S-1-12-*") and process.parent.executable != null and
  (
    (process.args : "/i" and process.args : ("/q", "/quiet") and process.args_count == 4 and
     process.args : ("?:\\Users\\*", "?:\\ProgramData\\*") and
     not process.parent.executable : ("?:\\Program Files (x86)\\*.exe",
                                      "?:\\Program Files\\*.exe",
                                      "?:\\Windows\\explorer.exe",
                                      "?:\\Users\\*\\Desktop\\*",
                                      "?:\\Users\\*\\Downloads\\*",
                                      "?:\\programdata\\*")) or

    (process.args_count == 1 and not process.parent.executable : ("?:\\Windows\\explorer.exe", "?:\\Windows\\SysWOW64\\explorer.exe")) or

    (process.args : "/i" and process.args : ("/q", "/quiet") and process.args_count == 4 and
     (process.parent.args : "Schedule" or process.parent.name : "wmiprvse.exe" or
     process.parent.executable : "?:\\Users\\*\\AppData\\*" or
     (process.parent.name : ("powershell.exe", "cmd.exe") and length(process.parent.command_line) >= 200))) or

    (process.args : "/i" and process.args : ("/q", "/quiet") and process.args_count == 4 and
     ?process.working_directory : "?:\\" and process.parent.name : ("cmd.exe", "powershell.exe"))
  ) and

  /* noisy pattern */
  not (process.parent.executable : "?:\\Users\\*\\AppData\\Local\\Temp\\*" and ?process.parent.args_count >= 2 and
       process.args : "?:\\Users\\*\\AppData\\Local\\Temp\\*\\*.msi") and

  not process.args : ("?:\\Program Files (x86)\\*", "?:\\Program Files\\*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Msiexec
    * ID: T1218.007
    * Reference URL: [https://attack.mitre.org/techniques/T1218/007/](https://attack.mitre.org/techniques/T1218/007/)



