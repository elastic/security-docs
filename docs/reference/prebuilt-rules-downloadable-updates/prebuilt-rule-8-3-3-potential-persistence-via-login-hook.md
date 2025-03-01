---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-potential-persistence-via-login-hook.html
---

# Potential Persistence via Login Hook [prebuilt-rule-8-3-3-potential-persistence-via-login-hook]

Identifies the creation or modification of the login window property list (plist). Adversaries may modify plist files to run a program during system boot or user login for persistence.

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

* [https://github.com/D00MFist/PersistentJXA/blob/master/LoginScript.js](https://github.com/D00MFist/PersistentJXA/blob/master/LoginScript.js)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Persistence

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2975]

## Triage and analysis

Starting in Mac OS X 10.7 (Lion), users can specify certain applications to be re-opened when a user reboots their machine. This can be abused to establish or maintain persistence on a compromised system.

## Rule query [_rule_query_3457]

```js
event.category:"file" and not event.type:"deletion" and
 file.name:"com.apple.loginwindow.plist" and
 process.name:(* and not (systemmigrationd or DesktopServicesHelper or diskmanagementd or rsync or launchd or cfprefsd or xpcproxy or ManagedClient or MCXCompositor or backupd or "iMazing Profile Editor"
))
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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Plist File Modification
    * ID: T1647
    * Reference URL: [https://attack.mitre.org/techniques/T1647/](https://attack.mitre.org/techniques/T1647/)



