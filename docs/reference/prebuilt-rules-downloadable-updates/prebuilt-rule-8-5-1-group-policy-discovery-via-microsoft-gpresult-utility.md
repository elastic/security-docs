---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-5-1-group-policy-discovery-via-microsoft-gpresult-utility.html
---

# Group Policy Discovery via Microsoft GPResult Utility [prebuilt-rule-8-5-1-group-policy-discovery-via-microsoft-gpresult-utility]

Detects the usage of gpresult.exe to query group policy objects. Attackers may query group policy objects during the reconnaissance phase after compromising a system to gain a better understanding of the active directory environment and possible methods to escalate privileges or move laterally.

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
* Discovery
* Elastic Endgame

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4420]

```js
process where event.type == "start" and
(process.name: "gpresult.exe" or process.pe.original_file_name == "gprslt.exe") and process.args: ("/z", "/v", "/r", "/x")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Group Policy Discovery
    * ID: T1615
    * Reference URL: [https://attack.mitre.org/techniques/T1615/](https://attack.mitre.org/techniques/T1615/)



