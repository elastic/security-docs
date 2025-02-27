---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-persistence-via-login-or-logout-hook.html
---

# Persistence via Login or Logout Hook [prebuilt-rule-8-2-1-persistence-via-login-or-logout-hook]

Identifies use of the Defaults command to install a login or logoff hook in MacOS. An adversary may abuse this capability to establish persistence in an environment by inserting code to be executed at login or logout.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.virusbulletin.com/uploads/pdf/conference_slides/2014/Wardle-VB2014.pdf](https://www.virusbulletin.com/uploads/pdf/conference_slides/2014/Wardle-VB2014.pdf)
* [https://www.manpagez.com/man/1/defaults/](https://www.manpagez.com/man/1/defaults/)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Persistence

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2049]



## Rule query [_rule_query_2339]

```js
process where event.type == "start" and
 process.name == "defaults" and process.args == "write" and process.args in ("LoginHook", "LogoutHook") and
 not process.args :
       (
         "Support/JAMF/ManagementFrameworkScripts/logouthook.sh",
         "Support/JAMF/ManagementFrameworkScripts/loginhook.sh",
         "/Library/Application Support/JAMF/ManagementFrameworkScripts/logouthook.sh",
         "/Library/Application Support/JAMF/ManagementFrameworkScripts/loginhook.sh"
       )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Initialization Scripts
    * ID: T1037
    * Reference URL: [https://attack.mitre.org/techniques/T1037/](https://attack.mitre.org/techniques/T1037/)



