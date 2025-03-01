---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-suspicious-calendar-file-modification.html
---

# Suspicious Calendar File Modification [prebuilt-rule-8-4-2-suspicious-calendar-file-modification]

Identifies suspicious modifications of the calendar file by an unusual process. Adversaries may create a custom calendar notification procedure to execute a malicious program at a recurring interval to establish persistence.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*
* auditbeat-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://labs.f-secure.com/blog/operationalising-calendar-alerts-persistence-on-macos](https://labs.f-secure.com/blog/operationalising-calendar-alerts-persistence-on-macos)
* [https://github.com/FSecureLABS/CalendarPersist](https://github.com/FSecureLABS/CalendarPersist)
* [https://github.com/D00MFist/PersistentJXA/blob/master/CalendarPersist.js](https://github.com/D00MFist/PersistentJXA/blob/master/CalendarPersist.js)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Persistence

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3952]

```js
event.category:file and event.action:modification and
  file.path:/Users/*/Library/Calendars/*.calendar/Events/*.ics and
  process.executable:
  (* and not
    (
      /System/Library/* or
      /System/Applications/Calendar.app/Contents/MacOS/* or
      /System/Applications/Mail.app/Contents/MacOS/Mail or
      /usr/libexec/xpcproxy or
      /sbin/launchd or
      /Applications/*
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)



