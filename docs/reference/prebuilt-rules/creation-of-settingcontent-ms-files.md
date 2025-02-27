---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/creation-of-settingcontent-ms-files.html
---

# Creation of SettingContent-ms Files [creation-of-settingcontent-ms-files]

Identifies the suspicious creation of SettingContents-ms files, which have been used in attacks to achieve code execution while evading defenses.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*
* logs-windows.sysmon_operational-*
* endgame-*
* winlogbeat-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://posts.specterops.io/the-tale-of-settingcontent-ms-files-f1ea253e4d39](https://posts.specterops.io/the-tale-of-settingcontent-ms-files-f1ea253e4d39)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Defend
* Rule Type: BBR
* Data Source: Sysmon
* Data Source: Elastic Endgame

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_251]

```js
file where host.os.type == "windows" and event.type == "creation" and
  file.extension : "settingcontent-ms" and
  not file.path : (
    "?:\\*\\AppData\\Local\\Packages\\windows.immersivecontrolpanel_*\\LocalState\\Indexed\\Settings\\*",
    "\\Device\\HarddiskVolume*\\Windows\\WinSxS\\amd64_microsoft-windows-s..*\\*.settingcontent-ms"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: User Execution
    * ID: T1204
    * Reference URL: [https://attack.mitre.org/techniques/T1204/](https://attack.mitre.org/techniques/T1204/)

* Sub-technique:

    * Name: Malicious File
    * ID: T1204.002
    * Reference URL: [https://attack.mitre.org/techniques/T1204/002/](https://attack.mitre.org/techniques/T1204/002/)

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



