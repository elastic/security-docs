---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-2-uncommon-registry-persistence-change.html
---

# Uncommon Registry Persistence Change [prebuilt-rule-8-17-2-uncommon-registry-persistence-change]

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

**Version**: 212

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4817]

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



