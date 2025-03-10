---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-process-created-with-an-elevated-token.html
---

# Process Created with an Elevated Token [prebuilt-rule-8-4-2-process-created-with-an-elevated-token]

Identifies the creation of a process running as SYSTEM and impersonating a Windows core binary privileges. Adversaries may create a new process with a different token to escalate privileges and bypass access controls.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://lengjibo.github.io/token/](https://lengjibo.github.io/token/)
* [https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)

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

## Rule query [_rule_query_4270]

```js
/* This rule is only compatible with Elastic Endpoint 8.4+ */

process where event.action == "start" and

 /* CreateProcessWithToken and effective parent is a privileged MS native binary used as a target for token theft */
 user.id : "S-1-5-18"  and

 /* Token Theft target process usually running as service are located in one of the following paths */
 process.Ext.effective_parent.executable :
                ("?:\\Windows\\*.exe",
                 "?:\\Program Files\\*.exe",
                 "?:\\Program Files (x86)\\*.exe",
                 "?:\\ProgramData\\*") and

 not (process.Ext.effective_parent.executable : "?:\\Windows\\System32\\Utilman.exe" and
      process.parent.executable : "?:\\Windows\\System32\\Utilman.exe" and process.parent.args : "/debug") and

 not process.executable : ("?:\\Windows\\System32\\WerFault.exe",
                           "?:\\Windows\\SysWOW64\\WerFault.exe",
                           "?:\\Windows\\System32\\WerFaultSecure.exe",
                           "?:\\Windows\\SysWOW64\\WerFaultSecure.exe",
                           "?:\\windows\\system32\\WerMgr.exe",
                           "?:\\Windows\\SoftwareDistribution\\Download\\Install\\securityhealthsetup.exe")  and

 not process.parent.executable : ("?:\\Windows\\System32\\AtBroker.exe", "?:\\Windows\\system32\\svchost.exe", "?:\\Program Files (x86)\\*.exe", "?:\\Program Files\\*.exe", "?:\\Windows\\System32\\msiexec.exe",
 "C:\\Windows\\System32\\DriverStore\\*") and


 not (process.code_signature.trusted == true and
      process.code_signature.subject_name in ("philandro Software GmbH", "Freedom Scientific Inc.", "TeamViewer Germany GmbH", "Projector.is, Inc.", "TeamViewer GmbH", "Cisco WebEx LLC", "Dell Inc"))
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



