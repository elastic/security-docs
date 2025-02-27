---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-volume-shadow-copy-deletion-via-wmic.html
---

# Volume Shadow Copy Deletion via WMIC [prebuilt-rule-0-14-2-volume-shadow-copy-deletion-via-wmic]

Identifies use of wmic.exe for shadow copy deletion on endpoints. This commonly occurs in tandem with ransomware or other destructive attacks.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Impact

**Version**: 10

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1461]

```js
process where event.type in ("start", "process_started") and
  (process.name : "WMIC.exe" or process.pe.original_file_name == "wmic.exe") and
  process.args : "delete" and process.args : "shadowcopy"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Inhibit System Recovery
    * ID: T1490
    * Reference URL: [https://attack.mitre.org/techniques/T1490/](https://attack.mitre.org/techniques/T1490/)



