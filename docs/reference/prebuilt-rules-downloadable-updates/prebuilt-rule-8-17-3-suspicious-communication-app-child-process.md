---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-suspicious-communication-app-child-process.html
---

# Suspicious Communication App Child Process [prebuilt-rule-8-17-3-suspicious-communication-app-child-process]

Identifies suspicious child processes of communications apps, which can indicate a potential masquerading as the communication app or the exploitation of a vulnerability on the application causing it to execute code.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*

**Severity**: medium

**Risk score**: 47

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
* Data Source: Elastic Defend

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4847]

```js
process where host.os.type == "windows" and event.type == "start" and
  (
    /* Slack */
    (process.parent.name : "slack.exe" and not
      (
        (
          process.executable : (
            "?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Users\\*\\AppData\\Local\\Island\\Island\\Application\\Island.exe",
            "?:\\Users\\*\\AppData\\Roaming\\Zoom\\bin*\\Zoom.exe",
            "?:\\Windows\\System32\\rundll32.exe",
            "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe",
            "?:\\Windows\\System32\\notepad.exe",
            "?:\\Windows\\System32\\WerFault.exe",
            "?:\\Windows\\SysWOW64\\WerFault.exe",
            "?:\\Users\\*\\AppData\\Local\\Programs\\Opera\\opera.exe"
          ) and process.code_signature.trusted == true
        ) or
        (
          process.code_signature.subject_name : (
            "Slack Technologies, Inc.",
            "Slack Technologies, LLC"
          ) and process.code_signature.trusted == true
        ) or
        (
          (process.name : "powershell.exe" and process.command_line : "powershell.exe -c Invoke-WebRequest -Uri https://slackb.com/*") or
          (process.name : "cmd.exe" and process.command_line : "C:\\WINDOWS\\system32\\cmd.exe /d /s /c \"%windir%\\System32\\rundll32.exe User32.dll,SetFocus 0\"")
        )
      )
    ) or

    /* WebEx */
    (process.parent.name : ("CiscoCollabHost.exe", "WebexHost.exe") and not
      (
        (
          process.executable : (
            "?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Windows\\System32\\WerFault.exe",
            "?:\\Windows\\SysWOW64\\WerFault.exe",
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe",
            "?:\\Users\\*\\AppData\\Local\\Programs\\Opera\\opera.exe"
          ) and process.code_signature.trusted == true
        ) or
        (
          process.code_signature.subject_name : (
            "Cisco Systems, Inc.",
            "Cisco WebEx LLC",
            "Cisco Systems Inc."
          ) and process.code_signature.trusted == true
        )
      )
    ) or

    /* Teams */
    (process.parent.name : "Teams.exe" and not
      (
        (
          process.executable : (
            "?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Windows\\System32\\WerFault.exe",
            "?:\\Windows\\SysWOW64\\WerFault.exe",
            "?:\\Windows\\BrowserCore\\BrowserCore.exe",
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe"
          ) and process.code_signature.trusted == true
        ) or
        (
          process.code_signature.subject_name : (
            "Microsoft Corporation",
            "Microsoft 3rd Party Application Component"
          ) and process.code_signature.trusted == true
        ) or
        (
          (process.name : "taskkill.exe" and process.args : "Teams.exe")
        )
      )
    ) or

    /* Discord */
    (process.parent.name : "Discord.exe" and not
      (
        (
          process.executable : (
            "?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Windows\\System32\\reg.exe",
            "?:\\Windows\\SysWOW64\\reg.exe",
            "?:\\Windows\\System32\\WerFault.exe",
            "?:\\Windows\\SysWOW64\\WerFault.exe"
          ) and process.code_signature.trusted == true
        ) or
        (
          process.code_signature.subject_name : (
            "Discord Inc."
          ) and process.code_signature.trusted == true
        ) or
        (
          process.name : "cmd.exe" and
          (
            process.command_line : (
              "C:\\WINDOWS\\system32\\cmd.exe /d /s /c \"chcp\"",
              "C:\\WINDOWS\\system32\\cmd.exe /q /d /s /c \"C:\\Program^ Files\\NVIDIA^ Corporation\\NVSMI\\nvidia-smi.exe\""
            ) or
            process.args : (
              "C:\\WINDOWS/System32/nvidia-smi.exe",
              "C:\\WINDOWS\\System32\\nvidia-smi.exe",
              "C:\\Windows\\System32\\DriverStore\\FileRepository/*/nvidia-smi.exe*"
            )
          )
        )
      )
    ) or

    /* WhatsApp */
    (process.parent.name : "Whatsapp.exe" and not
      (
        (
          process.executable : (
            "?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Windows\\System32\\WerFault.exe",
            "?:\\Windows\\SysWOW64\\WerFault.exe",
            "?:\\Windows\\System32\\reg.exe",
            "?:\\Windows\\SysWOW64\\reg.exe"
          ) and process.code_signature.trusted == true
        ) or
        (
          process.code_signature.subject_name : (
            "WhatsApp LLC",
            "WhatsApp, Inc",
            "24803D75-212C-471A-BC57-9EF86AB91435"
          ) and process.code_signature.trusted == true
        ) or
        (
          (process.name : "cmd.exe" and process.command_line : "C:\\Windows\\system32\\cmd.exe /d /s /c \"C:\\Windows\\system32\\wbem\\wmic.exe*")
        )
      )
    ) or

    /* Zoom */
    (process.parent.name : "Zoom.exe" and not
      (
        (
          process.executable : (
            "?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
            "?:\\Users\\*\\AppData\\Local\\Island\\Island\\Application\\Island.exe",
            "?:\\Users\\*\\AppData\\Local\\Mozilla Firefox\\firefox.exe",
            "?:\\Windows\\System32\\WerFault.exe",
            "?:\\Windows\\SysWOW64\\WerFault.exe"
          ) and process.code_signature.trusted == true
        ) or
        (
          process.code_signature.subject_name : (
            "Zoom Video Communications, Inc."
          ) and process.code_signature.trusted == true
        )
      )
    ) or

    /* Thunderbird */
    (process.parent.name : "thunderbird.exe" and not
      (
        (
          process.executable : (
            "?:\\Program Files\\*",
            "?:\\Program Files (x86)\\*",
            "?:\\Windows\\System32\\WerFault.exe",
            "?:\\Windows\\SysWOW64\\WerFault.exe",
            "?:\\Windows\\splwow64.exe"
          ) and process.code_signature.trusted == true
        ) or
        (
          process.code_signature.subject_name : (
            "Mozilla Corporation"
          ) and process.code_signature.trusted == true
        )
      )
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



