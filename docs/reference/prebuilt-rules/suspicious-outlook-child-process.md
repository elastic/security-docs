---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-outlook-child-process.html
---

# Suspicious Outlook Child Process [suspicious-outlook-child-process]

Identifies suspicious child processes spawned by MS Outlook, which can indicate a potential masquerading or the exploitation of a vulnerability on the application causing it to execute code.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Persistence
* Rule Type: BBR
* Data Source: Elastic Defend

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1063]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "outlook.exe" and
  not (
    (
      process.executable : (
        "?:\\Program Files\\*",
        "?:\\Program Files (x86)\\*",
        "?:\\Windows\\System32\\WerFault.exe",
        "?:\\Windows\\SysWOW64\\WerFault.exe",
        "?:\\Windows\\system32\\wermgr.exe",
        "?:\\Users\\*\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
        "?:\\Users\\*\\AppData\\Local\\Temp\\NewOutlookInstall\\NewOutlookInstaller.exe",
        "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
        "?:\\Users\\*\\AppData\\Local\\Island\\Island\\Application\\Island.exe",
        "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe",
        "?:\\Users\\*\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe",
        "?:\\Windows\\System32\\IME\\SHARED\\IMEWDBLD.EXE",
        "?:\\Windows\\System32\\spool\\drivers\\x64\\*",
        "?:\\Windows\\System32\\prevhost.exe",
        "?:\\Windows\\System32\\dwwin.exe",
        "?:\\Windows\\System32\\mspaint.exe",
        "?:\\Windows\\SysWOW64\\mspaint.exe",
        "?:\\Windows\\System32\\notepad.exe",
        "?:\\Windows\\SysWOW64\\notepad.exe",
        "?:\\Windows\\System32\\smartscreen.exe",
        "?:\\Windows\\explorer.exe",
        "?:\\Windows\\splwow64.exe"
      ) and process.code_signature.trusted == true
    ) or
    (
      process.name : "rundll32.exe" and
      process.args : "*hpmsn???.dll,MonitorPrintJobStatus*"
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Invalid Code Signature
    * ID: T1036.001
    * Reference URL: [https://attack.mitre.org/techniques/T1036/001/](https://attack.mitre.org/techniques/T1036/001/)

* Sub-technique:

    * Name: Match Legitimate Name or Location
    * ID: T1036.005
    * Reference URL: [https://attack.mitre.org/techniques/T1036/005/](https://attack.mitre.org/techniques/T1036/005/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Compromise Host Software Binary
    * ID: T1554
    * Reference URL: [https://attack.mitre.org/techniques/T1554/](https://attack.mitre.org/techniques/T1554/)



