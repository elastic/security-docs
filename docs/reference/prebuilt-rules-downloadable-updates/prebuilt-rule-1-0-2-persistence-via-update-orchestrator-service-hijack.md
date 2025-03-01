---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-persistence-via-update-orchestrator-service-hijack.html
---

# Persistence via Update Orchestrator Service Hijack [prebuilt-rule-1-0-2-persistence-via-update-orchestrator-service-hijack]

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

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1654]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1916]

```js
process where event.type == "start" and
  process.parent.executable : "C:\\Windows\\System32\\svchost.exe" and
  process.parent.args : "UsoSvc" and
  not process.executable :
         (
          "C:\\Windows\\System32\\UsoClient.exe",
          "C:\\Windows\\System32\\MusNotification.exe",
          "C:\\Windows\\System32\\MusNotificationUx.exe",
          "C:\\Windows\\System32\\MusNotifyIcon.exe",
          "C:\\Windows\\System32\\WerFault.exe",
          "C:\\Windows\\System32\\WerMgr.exe"
          )
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



