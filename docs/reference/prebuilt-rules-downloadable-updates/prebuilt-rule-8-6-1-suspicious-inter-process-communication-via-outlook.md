---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-6-1-suspicious-inter-process-communication-via-outlook.html
---

# Suspicious Inter-Process Communication via Outlook [prebuilt-rule-8-6-1-suspicious-inter-process-communication-via-outlook]

Detects Inter-Process Communication with Outlook via Component Object Model from an unusual process. Adversaries may target user email to collect sensitive information or send email on their behalf via API.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/apt29/Archive/CALDERA_DIY/evals/payloads/stepSeventeen_email.ps1](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/apt29/Archive/CALDERA_DIY/evals/payloads/stepSeventeen_email.ps1)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Collection

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4523]

```js
process where event.action == "start" and process.name : "OUTLOOK.EXE"  and
 process.Ext.effective_parent.name != null and
 not process.Ext.effective_parent.executable : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Email Collection
    * ID: T1114
    * Reference URL: [https://attack.mitre.org/techniques/T1114/](https://attack.mitre.org/techniques/T1114/)

* Sub-technique:

    * Name: Local Email Collection
    * ID: T1114.001
    * Reference URL: [https://attack.mitre.org/techniques/T1114/001/](https://attack.mitre.org/techniques/T1114/001/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Inter-Process Communication
    * ID: T1559
    * Reference URL: [https://attack.mitre.org/techniques/T1559/](https://attack.mitre.org/techniques/T1559/)

* Sub-technique:

    * Name: Component Object Model
    * ID: T1559.001
    * Reference URL: [https://attack.mitre.org/techniques/T1559/001/](https://attack.mitre.org/techniques/T1559/001/)



