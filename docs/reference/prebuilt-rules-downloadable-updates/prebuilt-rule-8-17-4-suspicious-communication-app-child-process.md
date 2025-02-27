---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-communication-app-child-process.html
---

# Suspicious Communication App Child Process [prebuilt-rule-8-17-4-suspicious-communication-app-child-process]

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
* Resources: Investigation Guide

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4753]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Communication App Child Process**

Communication apps like Slack, WebEx, and Teams are integral to modern workflows, facilitating collaboration. However, adversaries can exploit these apps by spawning unauthorized child processes, potentially masquerading as legitimate ones or exploiting vulnerabilities to execute malicious code. The detection rule identifies such anomalies by monitoring child processes of these apps, ensuring they are trusted and signed by recognized entities. This helps in identifying potential threats that deviate from expected behavior, thus safeguarding against unauthorized access and execution.

**Possible investigation steps**

* Review the process details, including the parent process name and executable path, to confirm if the child process is expected or unusual for the communication app in question.
* Check the code signature of the suspicious child process to determine if it is trusted and signed by a recognized entity, as specified in the query.
* Investigate the command line arguments of the child process to identify any potentially malicious or unexpected commands being executed.
* Correlate the event with other logs or alerts to identify any related suspicious activities or patterns, such as repeated unauthorized child process executions.
* Assess the user account associated with the process to determine if it has been compromised or is exhibiting unusual behavior.
* Examine the network activity of the affected system to identify any suspicious outbound connections that may indicate data exfiltration or communication with a command and control server.

**False positive analysis**

* Legitimate software updates or installations may trigger the rule if they spawn child processes from communication apps. Users can create exceptions for known update processes by verifying their code signatures and paths.
* Custom scripts or automation tools that interact with communication apps might be flagged. Users should ensure these scripts are signed and located in trusted directories, then add them to the exception list.
* Certain administrative tasks, such as using command-line tools like cmd.exe or powershell.exe, may be mistakenly identified as suspicious. Users can whitelist specific command lines or arguments that are regularly used in their environment.
* Some third-party integrations with communication apps may generate child processes that are not inherently malicious. Users should verify the legitimacy of these integrations and add them to the trusted list if they are deemed safe.
* Regularly review and update the list of trusted code signatures and executable paths to ensure that legitimate processes are not inadvertently flagged as suspicious.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or execution of malicious code.
* Terminate any suspicious child processes identified by the detection rule that are not signed by recognized entities or are executing from unexpected locations.
* Conduct a thorough review of the affected communication app’s logs and configurations to identify any unauthorized changes or access patterns.
* Restore the affected system from a known good backup if malicious activity is confirmed, ensuring that the backup is free from compromise.
* Update the communication app and all related software to the latest versions to patch any known vulnerabilities that may have been exploited.
* Implement application whitelisting to ensure only trusted and signed applications can execute, reducing the risk of similar threats.
* Escalate the incident to the security operations center (SOC) or relevant security team for further investigation and to assess the potential impact on other systems.


## Rule query [_rule_query_5708]

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



