---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-unexpected-child-process-of-macos-screensaver-engine.html
---

# Unexpected Child Process of macOS Screensaver Engine [prebuilt-rule-1-0-2-unexpected-child-process-of-macos-screensaver-engine]

Identifies when a child process is spawned by the screensaver engine process, which is consistent with an attacker’s malicious payload being executed after the screensaver activated on the endpoint. An adversary can maintain persistence on a macOS endpoint by creating a malicious screensaver (.saver) file and configuring the screensaver plist file to execute code each time the screensaver is activated.

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

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1487]

## Triage and analysis

- Analyze the descendant processes of the ScreenSaverEngine process for malicious code and suspicious behavior such
as a download of a payload from a server.
- Review the installed and activated screensaver on the host. Triage the screensaver (.saver) file that was triggered to
identify whether the file is malicious or not.


## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1722]

```js
process where event.type == "start" and process.parent.name == "ScreenSaverEngine"
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



