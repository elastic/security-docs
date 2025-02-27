---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-screensaver-plist-file-modified-by-unexpected-process.html
---

# Screensaver Plist File Modified by Unexpected Process [prebuilt-rule-0-14-2-screensaver-plist-file-modified-by-unexpected-process]

Identifies when a screensaver plist file is modified by an unexpected process. An adversary can maintain persistence on a macOS endpoint by creating a malicious screensaver (.saver) file and configuring the screensaver plist file to execute code each time the screensaver is activated.

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

* [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Persistence

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1300]

## Triage and analysis

- Analyze the plist file modification event to identify whether the change was expected or not
- Investigate the process that modified the plist file for malicious code or other suspicious behavior
- Identify if any suspicious or known malicious screensaver (.saver) files were recently written to or modified on the host

## Rule query [_rule_query_1398]

```js
file where event.type != "deletion" and
  file.name: "com.apple.screensaver.*.plist" and
  file.path : (
    "/Users/*/Library/Preferences/ByHost/*",
    "/Library/Managed Preferences/*",
    "/System/Library/Preferences/*"
    ) and
  /* Filter OS processes modifying screensaver plist files */
  not process.executable : (
    "/usr/sbin/cfprefsd",
    "/usr/libexec/xpcproxy",
    "/System/Library/CoreServices/ManagedClient.app/Contents/Resources/MCXCompositor",
    "/System/Library/CoreServices/ManagedClient.app/Contents/MacOS/ManagedClient"
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



