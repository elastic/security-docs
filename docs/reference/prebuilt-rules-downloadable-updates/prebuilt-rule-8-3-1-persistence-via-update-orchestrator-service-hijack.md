---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-persistence-via-update-orchestrator-service-hijack.html
---

# Persistence via Update Orchestrator Service Hijack [prebuilt-rule-8-3-1-persistence-via-update-orchestrator-service-hijack]

Identifies potential hijacking of the Microsoft Update Orchestrator Service to establish persistence with an integrity level of SYSTEM.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/irsl/CVE-2020-1313](https://github.com/irsl/CVE-2020-1313)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence
* CVE-2020-1313

**Version**: 100

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2329]



## Rule query [_rule_query_2692]

```js
process where event.type == "start" and
  process.parent.executable : "C:\\Windows\\System32\\svchost.exe" and
  process.parent.args : "UsoSvc" and
  not process.executable :
          ("?:\\ProgramData\\Microsoft\\Windows\\UUS\\Packages\\*\\amd64\\MoUsoCoreWorker.exe",
          "?:\\Windows\\System32\\UsoClient.exe",
          "?:\\Windows\\System32\\MusNotification.exe",
          "?:\\Windows\\System32\\MusNotificationUx.exe",
          "?:\\Windows\\System32\\MusNotifyIcon.exe",
          "?:\\Windows\\System32\\WerFault.exe",
          "?:\\Windows\\System32\\WerMgr.exe",
          "?:\\Windows\\UUS\\amd64\\MoUsoCoreWorker.exe",
          "?:\\Windows\\System32\\MoUsoCoreWorker.exe",
          "?:\\Windows\\UUS\\amd64\\UsoCoreWorker.exe",
          "?:\\Windows\\System32\\UsoCoreWorker.exe",
          "?:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\OfficeC2RClient.exe") and
  not process.name : ("MoUsoCoreWorker.exe", "OfficeC2RClient.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Windows Service
    * ID: T1543.003
    * Reference URL: [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)



