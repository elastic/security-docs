---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-enumeration-of-privileged-local-groups-membership.html
---

# Enumeration of Privileged Local Groups Membership [prebuilt-rule-0-14-3-enumeration-of-privileged-local-groups-membership]

Identifies instances of an unusual process enumerating built-in Windows privileged local groups membership like Administrators or Remote Desktop users.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 43

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Discovery

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1341]

## Config

This will require Windows security event 4799 by enabling audit success for the windows Account Management category and
the Security Group Management subcategory.

## Rule query [_rule_query_1516]

```js
iam where event.action == "user-member-enumerated" and

 /* noisy and usual legit processes excluded */
 not winlog.event_data.CallerProcessName:
              ("?:\\Windows\\System32\\VSSVC.exe",
               "?:\\Windows\\System32\\SearchIndexer.exe",
               "?:\\Windows\\System32\\CompatTelRunner.exe",
               "?:\\Windows\\System32\\oobe\\msoobe.exe",
               "?:\\Windows\\System32\\net1.exe",
               "?:\\Windows\\System32\\svchost.exe",
               "?:\\Windows\\System32\\Netplwiz.exe",
               "?:\\Windows\\System32\\msiexec.exe",
               "?:\\Windows\\System32\\CloudExperienceHostBroker.exe",
               "?:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
               "?:\\Windows\\System32\\SrTasks.exe",
               "?:\\Windows\\System32\\lsass.exe",
               "?:\\Windows\\System32\\diskshadow.exe",
               "?:\\Windows\\System32\\dfsrs.exe",
               "?:\\Program Files\\*.exe",
               "?:\\Program Files (x86)\\*.exe") and
  /* privileged local groups */
 (group.name:("admin*","RemoteDesktopUsers") or
  winlog.event_data.TargetSid:("S-1-5-32-544","S-1-5-32-555"))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Permission Groups Discovery
    * ID: T1069
    * Reference URL: [https://attack.mitre.org/techniques/T1069/](https://attack.mitre.org/techniques/T1069/)

* Sub-technique:

    * Name: Local Groups
    * ID: T1069.001
    * Reference URL: [https://attack.mitre.org/techniques/T1069/001/](https://attack.mitre.org/techniques/T1069/001/)



