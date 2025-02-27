---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-suspicious-wmic-xsl-script-execution.html
---

# Suspicious WMIC XSL Script Execution [prebuilt-rule-8-3-1-suspicious-wmic-xsl-script-execution]

Identifies WMIC allowlist bypass techniques by alerting on suspicious execution of scripts. When WMIC loads scripting libraries it may be indicative of an allowlist bypass.

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

**Version**: 100

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2666]

```js
sequence by process.entity_id with maxspan = 2m
[process where event.type in ("start", "process_started") and
   (process.name : "WMIC.exe" or process.pe.original_file_name : "wmic.exe") and
   process.args : ("format*:*", "/format*:*", "*-format*:*") and
   not process.command_line : "* /format:table *"]
[any where (event.category == "library" or (event.category == "process" and event.action : "Image loaded*")) and
 (dll.name : ("jscript.dll", "vbscript.dll") or file.name : ("jscript.dll", "vbscript.dll"))]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: XSL Script Processing
    * ID: T1220
    * Reference URL: [https://attack.mitre.org/techniques/T1220/](https://attack.mitre.org/techniques/T1220/)



