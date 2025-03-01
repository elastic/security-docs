---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-unusual-process-execution-path-alternate-data-stream.html
---

# Unusual Process Execution Path - Alternate Data Stream [prebuilt-rule-8-4-1-unusual-process-execution-path-alternate-data-stream]

Identifies processes running from an Alternate Data Stream. This is uncommon for legitimate processes and sometimes done by adversaries to hide malware.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*
* endgame-*

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
* Elastic Endgame

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2763]



## Rule query [_rule_query_3161]

```js
process where event.type == "start" and
  process.args : "?:\\*:*" and process.args_count == 1
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hide Artifacts
    * ID: T1564
    * Reference URL: [https://attack.mitre.org/techniques/T1564/](https://attack.mitre.org/techniques/T1564/)

* Sub-technique:

    * Name: NTFS File Attributes
    * ID: T1564.004
    * Reference URL: [https://attack.mitre.org/techniques/T1564/004/](https://attack.mitre.org/techniques/T1564/004/)



