---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-uncommon-registry-persistence-change.html
---

# Uncommon Registry Persistence Change [prebuilt-rule-8-17-4-uncommon-registry-persistence-change]

Detects changes to registry persistence keys that are not commonly used or modified by legitimate programs. This could be an indication of an adversary’s attempt to persist in a stealthy manner.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* logs-windows.sysmon_operational-*
* winlogbeat-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
* [https://github.com/rad9800/BootExecuteEDR](https://github.com/rad9800/BootExecuteEDR)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 213

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4923]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Uncommon Registry Persistence Change**

Windows Registry is a critical system database storing configuration settings. Adversaries exploit registry keys for persistence, ensuring malicious code executes on startup or during specific events. The detection rule identifies unusual modifications to less commonly altered registry keys, which may indicate stealthy persistence attempts. It filters out benign changes by excluding known legitimate processes and paths, focusing on suspicious alterations.

**Possible investigation steps**

* Review the specific registry path and value that triggered the alert to understand the context of the change and its potential impact on system behavior.
* Identify the process responsible for the registry modification by examining the process.name and process.executable fields, and determine if it is a known legitimate process or potentially malicious.
* Check the registry.data.strings field to see the new data or command being set in the registry key, and assess whether it aligns with known legitimate software or suspicious activity.
* Investigate the user account associated with the registry change by reviewing the HKEY_USERS path, if applicable, to determine if the change was made by an authorized user or an unexpected account.
* Correlate the alert with other recent events on the host, such as file modifications or network connections, to identify any additional indicators of compromise or related suspicious activity.
* Consult threat intelligence sources or databases to see if the registry path or process involved is associated with known malware or adversary techniques.

**False positive analysis**

* Legitimate software installations or updates may modify registry keys for setup or configuration purposes. Users can create exceptions for known software paths like C:\Program Files\*.exe to reduce noise.
* System maintenance processes such as Windows Update might trigger changes in registry keys like SetupExecute. Exclude processes like TiWorker.exe and poqexec.exe when they match known update patterns.
* Administrative scripts or tools that automate system configurations can alter registry keys. Identify and exclude these scripts by their executable paths or process names to prevent false alerts.
* Security software, including antivirus or endpoint protection, may interact with registry keys for monitoring purposes. Exclude paths related to these tools, such as C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe, to avoid false positives.
* User-initiated changes through control panel settings or personalization options can affect registry keys like SCRNSAVE.EXE. Exclude common system paths like %windir%\system32\rundll32.exe user32.dll,LockWorkStation to minimize false detections.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of potential malicious activity.
* Terminate any suspicious processes identified in the alert, particularly those not matching known legitimate executables or paths.
* Restore any altered registry keys to their original state using a known good backup or by manually resetting them to default values.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or processes.
* Review and update endpoint protection policies to ensure that similar registry changes are monitored and alerted on in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Document the incident, including all actions taken, to improve future response efforts and update threat intelligence databases.


## Rule query [_rule_query_5878]

```js
registry where host.os.type == "windows" and event.type == "change" and
 length(registry.data.strings) > 0 and
 registry.path : (
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Runonce\\*",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Load",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\IconServiceLib",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AppSetup",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Taskman",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\VmApplet",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Shell",
      "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff\\Script",
      "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logon\\Script",
      "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Shutdown\\Script",
      "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Startup\\Script",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Shell",
      "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff\\Script",
      "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logon\\Script",
      "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Shutdown\\Script",
      "HKEY_USERS\\*\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Startup\\Script",
      "HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\*\\ShellComponent",
      "HKLM\\SOFTWARE\\Microsoft\\Windows CE Services\\AutoStartOnConnect\\MicrosoftActiveSync",
      "HKLM\\SOFTWARE\\Microsoft\\Windows CE Services\\AutoStartOnDisconnect\\MicrosoftActiveSync",
      "HKLM\\SOFTWARE\\Microsoft\\Ctf\\LangBarAddin\\*\\FilePath",
      "HKLM\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Exec",
      "HKLM\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Script",
      "HKLM\\SOFTWARE\\Microsoft\\Command Processor\\Autorun",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Ctf\\LangBarAddin\\*\\FilePath",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Exec",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions\\*\\Script",
      "HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Command Processor\\Autorun",
      "HKEY_USERS\\*\\Control Panel\\Desktop\\scrnsave.exe",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\VerifierDlls",
      "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GpExtensions\\*\\DllName",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\SafeBoot\\AlternateShell",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\Terminal Server\\Wds\\rdpwd\\StartupPrograms",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\InitialProgram",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\Session Manager\\BootExecute",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\Session Manager\\BootExecuteNoPnpSync",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\Session Manager\\SetupExecute",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\Session Manager\\SetupExecuteNoPnpSync",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\Session Manager\\PlatformExecute",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\Session Manager\\Execute",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\Session Manager\\S0InitialCommand",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\ServiceControlManagerExtension",
      "HKLM\\SYSTEM\\ControlSet*\\Control\\BootVerificationProgram\\ImagePath",
      "HKLM\\SYSTEM\\Setup\\CmdLine",
      "HKEY_USERS\\*\\Environment\\UserInitMprLogonScript") and

 not registry.data.strings : ("C:\\Windows\\system32\\userinit.exe", "cmd.exe", "C:\\Program Files (x86)\\*.exe",
                              "C:\\Program Files\\*.exe") and
 not (process.name : "rundll32.exe" and registry.path : "*\\Software\\Microsoft\\Internet Explorer\\Extensions\\*\\Script") and
 not process.executable : ("C:\\Windows\\System32\\msiexec.exe",
                           "C:\\Windows\\SysWOW64\\msiexec.exe",
                           "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MsMpEng.exe",
                           "C:\\Program Files\\*.exe",
                           "C:\\Program Files (x86)\\*.exe") and
 not (process.name : ("TiWorker.exe", "poqexec.exe") and registry.value : "SetupExecute" and
      registry.data.strings : (
        "C:\\windows\\System32\\poqexec.exe /display_progress \\SystemRoot\\WinSxS\\pending.xml",
        "C:\\Windows\\System32\\poqexec.exe /skip_critical_poq /display_progress \\SystemRoot\\WinSxS\\pending.xml"
      )
     ) and
 not (process.name : "svchost.exe" and registry.value : "SCRNSAVE.EXE" and
      registry.data.strings : (
        "%windir%\\system32\\rundll32.exe user32.dll,LockWorkStation",
        "scrnsave.scr",
        "%windir%\\system32\\Ribbons.scr"
      )
     )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Screensaver
    * ID: T1546.002
    * Reference URL: [https://attack.mitre.org/techniques/T1546/002/](https://attack.mitre.org/techniques/T1546/002/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Registry Run Keys / Startup Folder
    * ID: T1547.001
    * Reference URL: [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)



