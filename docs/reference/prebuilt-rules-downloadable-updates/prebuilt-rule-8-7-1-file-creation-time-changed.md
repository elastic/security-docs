---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-file-creation-time-changed.html
---

# File Creation Time Changed [prebuilt-rule-8-7-1-file-creation-time-changed]

Identifies modification of a file creation time. Adversaries may modify file time attributes to blend malicious content with existing files. Timestomping is a technique that modifies the timestamps of a file often to mimic files that are in trusted directories.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*

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
* Defense Evasion

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4664]

```js
file where event.code : "2" and

 /* Requires Sysmon EventID 2 - File creation time change */
 event.action : "File creation time changed*" and

 not process.executable :
          ("?:\\Program Files\\*",
           "?:\\Program Files (x86)\\*",
           "?:\\Windows\\system32\\msiexec.exe",
           "?:\\Windows\\syswow64\\msiexec.exe",
           "?:\\Windows\\system32\\svchost.exe",
           "?:\\WINDOWS\\system32\\backgroundTaskHost.exe",
           "?:\\Users\\*\\AppData\\Local\\Google\\Chrome\\Application\\chrome.exe",
           "?:\\Users\\*\\AppData\\Local\\slack\\app-*\\slack.exe",
           "?:\\Users\\*\\AppData\\Local\\GitHubDesktop\\app-*\\GitHubDesktop.exe",
           "?:\\Users\\*\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",
           "?:\\Users\\*\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe") and
 not file.extension : ("tmp", "~tmp", "xml") and not user.name : ("SYSTEM", "Local Service", "Network Service")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)

* Sub-technique:

    * Name: Timestomp
    * ID: T1070.006
    * Reference URL: [https://attack.mitre.org/techniques/T1070/006/](https://attack.mitre.org/techniques/T1070/006/)



