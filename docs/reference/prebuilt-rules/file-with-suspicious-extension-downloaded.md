---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/file-with-suspicious-extension-downloaded.html
---

# File with Suspicious Extension Downloaded [file-with-suspicious-extension-downloaded]

Identifies unusual files downloaded from outside the local network that have the potential to be abused for code execution.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://x.com/Laughing_Mantis/status/1518766501385318406](https://x.com/Laughing_Mantis/status/1518766501385318406)
* [https://wikileaks.org/ciav7p1/cms/page_13763375.html](https://wikileaks.org/ciav7p1/cms/page_13763375.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Rule Type: BBR

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_361]

```js
file where host.os.type == "windows" and event.type == "creation" and
  file.extension : (
    "appinstaller", "application", "appx", "appxbundle", "cpl", "diagcab", "diagpkg", "diagcfg", "manifest",
    "msix", "pif", "search-ms", "searchConnector-ms", "settingcontent-ms", "symlink", "theme", "themepack"
  ) and file.Ext.windows.zone_identifier > 1 and
  not
  (
    (
      file.extension : "msix" and
      file.path : (
        "?:\\Users\\*\\AppData\\Local\\Temp\\WinGet\\Microsoft.Winget.Source*",
        "?:\\Windows\\system32\\config\\systemprofile\\AppData\\Local\\Microsoft\\WinGet\\State\\defaultState\\Microsoft.PreIndexed.Package\\Microsoft.Winget.Source*"
      )
    ) or
    (
      process.name : "Teams.exe" and process.code_signature.trusted == true and
      file.extension : "msix" and
      file.path : "?:\\Users\\*\\AppData\\Roaming\\Microsoft\\Teams\\tmp\\*"
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Phishing
    * ID: T1566
    * Reference URL: [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)

* Sub-technique:

    * Name: Spearphishing Attachment
    * ID: T1566.001
    * Reference URL: [https://attack.mitre.org/techniques/T1566/001/](https://attack.mitre.org/techniques/T1566/001/)

* Sub-technique:

    * Name: Spearphishing Link
    * ID: T1566.002
    * Reference URL: [https://attack.mitre.org/techniques/T1566/002/](https://attack.mitre.org/techniques/T1566/002/)



