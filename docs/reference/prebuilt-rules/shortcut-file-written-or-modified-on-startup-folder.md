---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/shortcut-file-written-or-modified-on-startup-folder.html
---

# Shortcut File Written or Modified on Startup Folder [shortcut-file-written-or-modified-on-startup-folder]

Identifies shortcut files written to or modified in the startup folder. Adversaries may use this technique to maintain persistence.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*

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
* Tactic: Persistence
* Data Source: Elastic Defend
* Rule Type: BBR

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_990]

```js
file where host.os.type == "windows" and event.type != "deletion" and file.extension == "lnk" and
  file.path : (
    "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\*"
  ) and
  not (
    (process.name : "ONENOTE.EXE" and process.code_signature.status: "trusted" and file.name : "*OneNote.lnk") or
    (process.name : "OktaVerifySetup.exe" and process.code_signature.status: "trusted" and file.name : "Okta Verify.lnk") or
    (process.name : "OneLaunch.exe" and process.code_signature.status: "trusted" and file.name : "OneLaunch*.lnk") or
    (process.name : "APPServerClient.exe" and process.code_signature.status: "trusted" and file.name : "Parallels Client.lnk")
  )
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

* Sub-technique:

    * Name: Shortcut Modification
    * ID: T1547.009
    * Reference URL: [https://attack.mitre.org/techniques/T1547/009/](https://attack.mitre.org/techniques/T1547/009/)



