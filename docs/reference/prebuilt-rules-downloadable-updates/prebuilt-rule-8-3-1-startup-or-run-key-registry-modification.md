---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-startup-or-run-key-registry-modification.html
---

# Startup or Run Key Registry Modification [prebuilt-rule-8-3-1-startup-or-run-key-registry-modification]

Identifies run key or startup key registry modifications. In order to survive reboots and other system interrupts, attackers will modify run keys within the registry or leverage startup folder items as a form of persistence.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 100

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2689]

```js
registry where registry.data.strings != null and
 registry.path : (
     /* Machine Hive */
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
     "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
     "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*",
     /* Users Hive */
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\*",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\*",
     "HKEY_USERS\\*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\\*"
     ) and
  /* add common legitimate changes without being too restrictive as this is one of the most abused AESPs */
  not registry.data.strings : "ctfmon.exe /n" and
  not (registry.value : "Application Restart #*" and process.name : "csrss.exe") and
  user.id not in ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
  not registry.data.strings : ("?:\\Program Files\\*.exe", "?:\\Program Files (x86)\\*.exe") and
  not process.executable : ("?:\\Windows\\System32\\msiexec.exe", "?:\\Windows\\SysWOW64\\msiexec.exe") and
  not (process.name : "OneDriveSetup.exe" and
       registry.value : ("Delete Cached Standalone Update Binary", "Delete Cached Update Binary", "amd64", "Uninstall *") and
       registry.data.strings : "?:\\Windows\\system32\\cmd.exe /q /c * \"?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\*\"")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Registry Run Keys / Startup Folder
    * ID: T1547.001
    * Reference URL: [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)



