---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-modification-of-boot-configuration.html
---

# Modification of Boot Configuration [prebuilt-rule-0-14-2-modification-of-boot-configuration]

Identifies use of bcdedit.exe to delete boot configuration data. This tactic is sometimes used as by malware or an attacker as a destructive technique.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

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
* Impact

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1458]

```js
process where event.type in ("start", "process_started") and
  (process.name : "bcdedit.exe" or process.pe.original_file_name == "bcdedit.exe") and
  (process.args : "/set" and process.args : "bootstatuspolicy" and process.args : "ignoreallfailures") or
  (process.args : "no" and process.args : "recoveryenabled")
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



