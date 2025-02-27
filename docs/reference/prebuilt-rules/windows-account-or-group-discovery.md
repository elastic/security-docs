---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/windows-account-or-group-discovery.html
---

# Windows Account or Group Discovery [windows-account-or-group-discovery]

This rule identifies the execution of commands that enumerates account or group information. Adversaries may use built-in applications to get a listing of local system or domain accounts and groups.

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
* Tactic: Discovery
* Rule Type: BBR
* Data Source: Elastic Defend

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1224]

```js
process where host.os.type == "windows" and event.type == "start" and
(
  (
   (
    (process.name : "net.exe" or process.pe.original_file_name == "net.exe") or
    (
     (process.name : "net1.exe" or process.pe.original_file_name == "net1.exe") and
     not process.parent.name : "net.exe"
    )
   ) and process.args : ("accounts", "group", "user", "localgroup") and not process.args : "/add"
  ) or
  (process.name:("dsquery.exe", "dsget.exe") and process.args:("*members*", "user")) or
  (process.name:"dsquery.exe" and process.args:"*filter*") or
  process.name:("quser.exe", "qwinsta.exe", "PsGetSID.exe", "PsLoggedOn.exe", "LogonSessions.exe", "whoami.exe") or
  (
    process.name: "cmd.exe" and
    (
      process.args : "echo" and process.args : (
        "%username%", "%userdomain%", "%userdnsdomain%",
        "%userdomain_roamingprofile%", "%userprofile%",
        "%homepath%", "%localappdata%", "%appdata%"
      ) or
      process.args : "set"
    )
  )
) and not process.parent.args: "C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Content\\DetectionScripts\\*.ps1"
and not process.parent.name : "LTSVC.exe" and not user.id : "S-1-5-18"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Permission Groups Discovery
    * ID: T1069
    * Reference URL: [https://attack.mitre.org/techniques/T1069/](https://attack.mitre.org/techniques/T1069/)

* Sub-technique:

    * Name: Local Groups
    * ID: T1069.001
    * Reference URL: [https://attack.mitre.org/techniques/T1069/001/](https://attack.mitre.org/techniques/T1069/001/)

* Sub-technique:

    * Name: Domain Groups
    * ID: T1069.002
    * Reference URL: [https://attack.mitre.org/techniques/T1069/002/](https://attack.mitre.org/techniques/T1069/002/)

* Technique:

    * Name: Account Discovery
    * ID: T1087
    * Reference URL: [https://attack.mitre.org/techniques/T1087/](https://attack.mitre.org/techniques/T1087/)

* Sub-technique:

    * Name: Local Account
    * ID: T1087.001
    * Reference URL: [https://attack.mitre.org/techniques/T1087/001/](https://attack.mitre.org/techniques/T1087/001/)

* Sub-technique:

    * Name: Domain Account
    * ID: T1087.002
    * Reference URL: [https://attack.mitre.org/techniques/T1087/002/](https://attack.mitre.org/techniques/T1087/002/)

* Technique:

    * Name: Password Policy Discovery
    * ID: T1201
    * Reference URL: [https://attack.mitre.org/techniques/T1201/](https://attack.mitre.org/techniques/T1201/)



