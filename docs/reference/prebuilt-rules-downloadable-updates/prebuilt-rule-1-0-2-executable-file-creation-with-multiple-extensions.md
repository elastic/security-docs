---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-executable-file-creation-with-multiple-extensions.html
---

# Executable File Creation with Multiple Extensions [prebuilt-rule-1-0-2-executable-file-creation-with-multiple-extensions]

Masquerading can allow an adversary to evade defenses and better blend in with the environment. One way it occurs is when the name or location of a file is manipulated as a means of tricking a user into executing what they think is a benign file type but is actually executable code.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1551]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1789]

```js
file where event.type == "creation" and file.extension : "exe" and
  file.name regex~ """.*\.(vbs|vbe|bat|js|cmd|wsh|ps1|pdf|docx?|xlsx?|pptx?|txt|rtf|gif|jpg|png|bmp|hta|txt|img|iso)\.exe"""
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Masquerade Task or Service
    * ID: T1036.004
    * Reference URL: [https://attack.mitre.org/techniques/T1036/004/](https://attack.mitre.org/techniques/T1036/004/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: User Execution
    * ID: T1204
    * Reference URL: [https://attack.mitre.org/techniques/T1204/](https://attack.mitre.org/techniques/T1204/)

* Sub-technique:

    * Name: Malicious File
    * ID: T1204.002
    * Reference URL: [https://attack.mitre.org/techniques/T1204/002/](https://attack.mitre.org/techniques/T1204/002/)



