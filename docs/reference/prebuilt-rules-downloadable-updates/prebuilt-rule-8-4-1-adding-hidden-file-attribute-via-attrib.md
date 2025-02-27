---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-adding-hidden-file-attribute-via-attrib.html
---

# Adding Hidden File Attribute via Attrib [prebuilt-rule-8-4-1-adding-hidden-file-attribute-via-attrib]

Adversaries can add the *hidden* attribute to files to hide them from the user in an attempt to evade detection.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: low

**Risk score**: 21

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

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2713]



## Rule query [_rule_query_3105]

```js
process where event.type == "start" and
  process.name : "attrib.exe" and process.args : "+h"
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

    * Name: Hidden Files and Directories
    * ID: T1564.001
    * Reference URL: [https://attack.mitre.org/techniques/T1564/001/](https://attack.mitre.org/techniques/T1564/001/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)



