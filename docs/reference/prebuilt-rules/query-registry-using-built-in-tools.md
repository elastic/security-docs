---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/query-registry-using-built-in-tools.html
---

# Query Registry using Built-in Tools [query-registry-using-built-in-tools]

This rule identifies the execution of commands that can be used to query the Windows Registry. Adversaries may query the registry to gain situational awareness about the host, like installed security software, programs and settings.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.process-*

**Severity**: low

**Risk score**: 21

**Runs every**: 12h

**Searches indices from**: now-24h ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Discovery
* Rule Type: BBR
* Data Source: Elastic Defend

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_904]

```js
host.os.type:windows and event.category:process and event.type:start and
  (
    (process.name.caseless:"reg.exe" and process.args:"query") or
    (process.name.caseless:("powershell.exe" or "powershell_ise.exe" or "pwsh.exe") and
     process.args:(
       ("get-childitem" or "Get-ChildItem" or "gci" or "dir" or "ls" or
        "get-item" or "Get-Item" or "gi" or
        "get-itemproperty" or "Get-ItemProperty" or "gp") and
       ("hkcu" or "HKCU" or "hkey_current_user" or "HKEY_CURRENT_USER" or
        "hkey_local_machine" or "HKEY_LOCAL_MACHINE" or
        "hklm" or "HKLM" or registry\:\:*)
      )
    )
  ) and
  not process.command_line : (
    "C:\\Windows\\system32\\reg.exe  query hklm\\software\\microsoft\\windows\\softwareinventorylogging /v collectionstate /reg:64" or
    "reg  query \"HKLM\\Software\\WOW6432Node\\Npcap\" /ve  "
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Query Registry
    * ID: T1012
    * Reference URL: [https://attack.mitre.org/techniques/T1012/](https://attack.mitre.org/techniques/T1012/)



