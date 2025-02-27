---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-enumeration-of-users-or-groups-via-built-in-commands.html
---

# Enumeration of Users or Groups via Built-in Commands [prebuilt-rule-8-2-1-enumeration-of-users-or-groups-via-built-in-commands]

Identifies the execution of macOS built-in commands related to account or group enumeration. Adversaries may use account and group information to orient themselves before deciding how to act.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Discovery

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2043]



## Rule query [_rule_query_2333]

```js
process where event.type in ("start", "process_started") and
  (
    process.name : ("ldapsearch", "dsmemberutil") or
    (process.name : "dscl" and
      process.args : ("read", "-read", "list", "-list", "ls", "search", "-search") and
      process.args : ("/Active Directory/*", "/Users*", "/Groups*"))
	) and
  not process.parent.executable : ("/Applications/NoMAD.app/Contents/MacOS/NoMAD",
     "/Applications/ZoomPresence.app/Contents/MacOS/ZoomPresence",
     "/Applications/Sourcetree.app/Contents/MacOS/Sourcetree",
     "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon",
     "/Applications/Jamf Connect.app/Contents/MacOS/Jamf Connect",
     "/usr/local/jamf/bin/jamf",
     "/Library/Application Support/AirWatch/hubd",
     "/opt/jc/bin/jumpcloud-agent",
     "/Applications/ESET Endpoint Antivirus.app/Contents/MacOS/esets_daemon",
     "/Applications/ESET Endpoint Security.app/Contents/MacOS/esets_daemon",
     "/Library/PrivilegedHelperTools/com.fortinet.forticlient.uninstall_helper"
    )
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

* Technique:

    * Name: Account Discovery
    * ID: T1087
    * Reference URL: [https://attack.mitre.org/techniques/T1087/](https://attack.mitre.org/techniques/T1087/)



