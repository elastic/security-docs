---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-13-3-parent-process-pid-spoofing.html
---

# Parent Process PID Spoofing [prebuilt-rule-0-13-3-parent-process-pid-spoofing]

Identifies parent process spoofing used to thwart detection. Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.didierstevens.com/2017/03/20/](https://blog.didierstevens.com/2017/03/20/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1296]

```js
/* This rule is compatible with Elastic Endpoint only */

sequence by host.id, user.id with maxspan=5m
 [process where event.type == "start" and
  process.Ext.token.integrity_level_name != "system" and
  (
    process.pe.original_file_name : ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "eqnedt32.exe",
                                     "fltldr.exe", "mspub.exe", "msaccess.exe", "powershell.exe", "pwsh.exe",
                                     "cscript.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe", "msbuild.exe",
                                     "mshta.exe", "wmic.exe", "cmstp.exe", "msxsl.exe") or
    process.executable : ("?:\\Users\\*.exe",
                          "?:\\ProgramData\\*.exe",
                          "?:\\Windows\\Microsoft.NET\\*.exe",
                          "?:\\Windows\\Temp\\*.exe",
                          "?:\\Windows\\Tasks\\*") or
    process.code_signature.trusted != true
  )
  ] by process.pid
 [process where event.type == "start" and process.parent.Ext.real.pid > 0 and
  /* process.parent.Ext.real.pid is only populated if the parent process pid doesn't match */

  not (process.name : "msedge.exe" and process.parent.name : "sihost.exe")
 ] by process.parent.Ext.real.pid
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Access Token Manipulation
    * ID: T1134
    * Reference URL: [https://attack.mitre.org/techniques/T1134/](https://attack.mitre.org/techniques/T1134/)

* Sub-technique:

    * Name: Parent PID Spoofing
    * ID: T1134.004
    * Reference URL: [https://attack.mitre.org/techniques/T1134/004/](https://attack.mitre.org/techniques/T1134/004/)



