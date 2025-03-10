---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-privileges-elevation-via-parent-process-pid-spoofing.html
---

# Privileges Elevation via Parent Process PID Spoofing [prebuilt-rule-8-4-1-privileges-elevation-via-parent-process-pid-spoofing]

Identifies parent process spoofing used to create an elevated child process. Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://gist.github.com/xpn/a057a26ec81e736518ee50848b9c2cd6](https://gist.github.com/xpn/a057a26ec81e736518ee50848b9c2cd6)
* [https://blog.didierstevens.com/2017/03/20/](https://blog.didierstevens.com/2017/03/20/)
* [https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1134.002/T1134.002.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1134.002/T1134.002.md)

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

## Rule query [_rule_query_2968]

```js
/* This rule is compatible with Elastic Endpoint only */

process where event.action == "start" and

 /* process creation via seclogon */
 process.parent.Ext.real.pid > 0 and

 /* PrivEsc to SYSTEM */
 user.id : "S-1-5-18"  and

 /* Common FPs - evasion via hollowing is possible, should be covered by code injection */
 not process.executable : ("?:\\Windows\\System32\\WerFault.exe",
                           "?:\\Windows\\SysWOW64\\WerFault.exe",
                           "?:\\Windows\\System32\\WerFaultSecure.exe",
                           "?:\\Windows\\SysWOW64\\WerFaultSecure.exe",
                           "?:\\Windows\\System32\\Wermgr.exe",
                           "?:\\Windows\\SysWOW64\\Wermgr.exe",
                           "?:\\Windows\\SoftwareDistribution\\Download\\Install\\securityhealthsetup.exe") and

 not process.parent.executable : "?:\\Windows\\System32\\AtBroker.exe" and

 not (process.code_signature.subject_name in
           ("philandro Software GmbH", "Freedom Scientific Inc.", "TeamViewer Germany GmbH", "Projector.is, Inc.",
            "TeamViewer GmbH", "Cisco WebEx LLC", "Dell Inc") and process.code_signature.trusted == true)
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

* Sub-technique:

    * Name: Create Process with Token
    * ID: T1134.002
    * Reference URL: [https://attack.mitre.org/techniques/T1134/002/](https://attack.mitre.org/techniques/T1134/002/)

* Sub-technique:

    * Name: Parent PID Spoofing
    * ID: T1134.004
    * Reference URL: [https://attack.mitre.org/techniques/T1134/004/](https://attack.mitre.org/techniques/T1134/004/)



