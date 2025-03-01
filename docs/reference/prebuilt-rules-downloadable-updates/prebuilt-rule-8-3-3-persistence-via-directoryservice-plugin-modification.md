---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-persistence-via-directoryservice-plugin-modification.html
---

# Persistence via DirectoryService Plugin Modification [prebuilt-rule-8-3-3-persistence-via-directoryservice-plugin-modification]

Identifies the creation or modification of a DirectoryService PlugIns (dsplug) file. The DirectoryService daemon launches on each system boot and automatically reloads after crash. It scans and executes bundles that are located in the DirectoryServices PlugIns folder and can be abused by adversaries to maintain persistence.

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

* [https://blog.chichou.me/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://blog.chichou.me/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)

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

## Rule query [_rule_query_3448]

```js
event.category:file and not event.type:deletion and
  file.path:/Library/DirectoryServices/PlugIns/*.dsplug
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)



