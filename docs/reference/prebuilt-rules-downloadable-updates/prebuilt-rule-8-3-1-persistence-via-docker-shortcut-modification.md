---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-persistence-via-docker-shortcut-modification.html
---

# Persistence via Docker Shortcut Modification [prebuilt-rule-8-3-1-persistence-via-docker-shortcut-modification]

An adversary can establish persistence by modifying an existing macOS dock property list in order to execute a malicious application instead of the intended one when invoked.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/specterops/presentations/raw/master/Leo%20Pitt/Hey_Im_Still_in_Here_Modern_macOS_Persistence_SO-CON2020.pdf](https://github.com/specterops/presentations/raw/master/Leo%20Pitt/Hey_Im_Still_in_Here_Modern_macOS_Persistence_SO-CON2020.pdf)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Persistence

**Version**: 100

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2645]

```js
event.category : file and event.action : modification and
 file.path : /Users/*/Library/Preferences/com.apple.dock.plist and
 not process.name : (xpcproxy or cfprefsd or plutil or jamf or PlistBuddy or InstallerRemotePluginService)
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



