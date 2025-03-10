---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-prompt-for-credentials-with-osascript.html
---

# Prompt for Credentials with OSASCRIPT [prebuilt-rule-1-0-2-prompt-for-credentials-with-osascript]

Identifies the use of osascript to execute scripts via standard input that may prompt a user for credentials with a rogue dialog.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/EmpireProject/EmPyre/blob/master/lib/modules/collection/osx/prompt.py](https://github.com/EmpireProject/EmPyre/blob/master/lib/modules/collection/osx/prompt.py)
* [https://ss64.com/osx/osascript.html](https://ss64.com/osx/osascript.md)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Credential Access

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1475]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1706]

```js
process where event.type in ("start", "process_started") and process.name : "osascript" and
 process.command_line : "osascript*display dialog*password*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Input Capture
    * ID: T1056
    * Reference URL: [https://attack.mitre.org/techniques/T1056/](https://attack.mitre.org/techniques/T1056/)

* Sub-technique:

    * Name: GUI Input Capture
    * ID: T1056.002
    * Reference URL: [https://attack.mitre.org/techniques/T1056/002/](https://attack.mitre.org/techniques/T1056/002/)



