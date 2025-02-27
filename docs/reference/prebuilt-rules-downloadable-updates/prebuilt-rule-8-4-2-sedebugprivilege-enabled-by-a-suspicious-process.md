---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-sedebugprivilege-enabled-by-a-suspicious-process.html
---

# SeDebugPrivilege Enabled by a Suspicious Process [prebuilt-rule-8-4-2-sedebugprivilege-enabled-by-a-suspicious-process]

Identifies the creation of a process running as SYSTEM and impersonating a Windows core binary privileges. Adversaries may create a new process with a different token to escalate privileges and bypass access controls.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4703](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4703)
* [https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3559]



## Rule query [_rule_query_4256]

```js
any where event.provider: "Microsoft-Windows-Security-Auditing" and
 event.action : "Token Right Adjusted Events" and

 winlog.event_data.EnabledPrivilegeList : "SeDebugPrivilege" and

 /* exclude processes with System Integrity  */
 not winlog.event_data.SubjectUserSid : ("S-1-5-18", "S-1-5-19", "S-1-5-20") and

 not winlog.event_data.ProcessName :
         ("?:\\Windows\\System32\\msiexec.exe",
          "?:\\Windows\\SysWOW64\\msiexec.exe",
          "?:\\Windows\\System32\\lsass.exe",
          "?:\\Windows\\WinSxS\\*",
          "?:\\Program Files\\*",
          "?:\\Program Files (x86)\\*",
          "?:\\Windows\\System32\\MRT.exe",
          "?:\\Windows\\System32\\cleanmgr.exe",
          "?:\\Windows\\System32\\taskhostw.exe",
          "?:\\Windows\\System32\\mmc.exe",
          "?:\\Users\\*\\AppData\\Local\\Temp\\*-*\\DismHost.exe",
          "?:\\Windows\\System32\\auditpol.exe",
          "?:\\Windows\\System32\\wbem\\WmiPrvSe.exe",
          "?:\\Windows\\SysWOW64\\wbem\\WmiPrvSe.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Access Token Manipulation
    * ID: T1134
    * Reference URL: [https://attack.mitre.org/techniques/T1134/](https://attack.mitre.org/techniques/T1134/)



