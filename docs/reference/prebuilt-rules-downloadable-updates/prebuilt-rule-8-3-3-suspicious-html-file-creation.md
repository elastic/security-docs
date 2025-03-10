---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-suspicious-html-file-creation.html
---

# Suspicious HTML File Creation [prebuilt-rule-8-3-3-suspicious-html-file-creation]

Identifies the execution of a browser process to open an HTML file with high entropy and size. Adversaries may smuggle data and files past content filters by hiding malicious payloads inside of seemingly benign HTML files.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Initial Access

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3138]



## Rule query [_rule_query_3658]

```js
sequence by user.id with maxspan=5m
 [file where event.action in ("creation", "rename") and
  file.extension : ("htm", "html") and
   file.path : ("?:\\Users\\*\\Downloads\\*",
                "?:\\Users\\*\\Content.Outlook\\*",
                "?:\\Users\\*\\AppData\\Local\\Temp\\Temp?_*",
                "?:\\Users\\*\\AppData\\Local\\Temp\\7z*",
                "?:\\Users\\*\\AppData\\Local\\Temp\\Rar$*") and
   ((file.Ext.entropy >= 5 and file.size >= 150000) or file.size >= 1000000)]
 [process where event.action == "start" and
  (
   (process.name in ("chrome.exe", "msedge.exe", "brave.exe", "whale.exe", "browser.exe", "dragon.exe", "vivaldi.exe", "opera.exe")
    and process.args == "--single-argument") or
   (process.name == "iexplore.exe" and process.args_count == 2) or
   (process.name in ("firefox.exe", "waterfox.exe") and process.args == "-url")
  )
  and process.args : ("?:\\Users\\*\\Downloads\\*.htm*",
                      "?:\\Users\\*\\Content.Outlook\\*.htm*",
                      "?:\\Users\\*\\AppData\\Local\\Temp\\Temp?_*.htm*",
                      "?:\\Users\\*\\AppData\\Local\\Temp\\7z*.htm*",
                      "?:\\Users\\*\\AppData\\Local\\Temp\\Rar$*.htm*")]
```

**Framework**: MITRE ATT&CKTM

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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Obfuscated Files or Information
    * ID: T1027
    * Reference URL: [https://attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/)

* Sub-technique:

    * Name: HTML Smuggling
    * ID: T1027.006
    * Reference URL: [https://attack.mitre.org/techniques/T1027/006/](https://attack.mitre.org/techniques/T1027/006/)



