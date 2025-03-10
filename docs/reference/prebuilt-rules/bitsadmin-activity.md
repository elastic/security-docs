---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/bitsadmin-activity.html
---

# Bitsadmin Activity [bitsadmin-activity]

Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism. Adversaries may abuse BITS to persist, download, execute, and even clean up after running malicious code.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* winlogbeat-*

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
* Tactic: Command and Control
* Data Source: Elastic Defend
* Rule Type: BBR
* Data Source: Sysmon
* Data Source: Elastic Endgame
* Data Source: System

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_220]

```js
process where host.os.type == "windows" and event.type == "start" and
  (
   (process.name : "bitsadmin.exe" and process.args : (
        "*Transfer*", "*Create*", "AddFile", "*SetNotifyFlags*", "*SetNotifyCmdLine*",
        "*SetMinRetryDelay*", "*SetCustomHeaders*", "*Resume*")
   ) or
   (process.name : "powershell.exe" and process.args : (
        "*Start-BitsTransfer*", "*Add-BitsFile*",
        "*Resume-BitsTransfer*", "*Set-BitsTransfer*", "*BITS.Manager*")
   )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Ingress Tool Transfer
    * ID: T1105
    * Reference URL: [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: BITS Jobs
    * ID: T1197
    * Reference URL: [https://attack.mitre.org/techniques/T1197/](https://attack.mitre.org/techniques/T1197/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: BITS Jobs
    * ID: T1197
    * Reference URL: [https://attack.mitre.org/techniques/T1197/](https://attack.mitre.org/techniques/T1197/)



