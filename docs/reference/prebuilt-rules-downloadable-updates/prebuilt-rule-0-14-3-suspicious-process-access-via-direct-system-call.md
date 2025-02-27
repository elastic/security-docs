---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-suspicious-process-access-via-direct-system-call.html
---

# Suspicious Process Access via Direct System Call [prebuilt-rule-0-14-3-suspicious-process-access-via-direct-system-call]

Identifies suspicious process access events from an unknown memory region. Endpoint security solutions usually hook userland Windows APIs in order to decide if the code that is being executed is malicious or not. It’s possible to bypass hooked functions by writing malicious functions that call syscalls directly.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://twitter.com/SBousseaden/status/1278013896440324096](https://twitter.com/SBousseaden/status/1278013896440324096)
* [https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs](https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1513]

```js
process where event.code == "10" and
 length(winlog.event_data.CallTrace) > 0 and

 /* Sysmon CallTrace starting with unknown memory module instead of ntdll which host Windows NT Syscalls */
 not winlog.event_data.CallTrace : ("?:\\WINDOWS\\SYSTEM32\\ntdll.dll*", "?:\\WINDOWS\\SysWOW64\\ntdll.dll*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)



