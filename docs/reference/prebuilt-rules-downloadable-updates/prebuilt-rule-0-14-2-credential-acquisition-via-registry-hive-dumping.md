---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-credential-acquisition-via-registry-hive-dumping.html
---

# Credential Acquisition via Registry Hive Dumping [prebuilt-rule-0-14-2-credential-acquisition-via-registry-hive-dumping]

Identifies attempts to export a registry hive which may contain credentials using the Windows reg.exe tool.

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

**References**:

* [https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-the-registry-7512674487f8](https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-the-registry-7512674487f8)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Credential Access

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1423]

```js
process where event.type in ("start", "process_started") and
 process.pe.original_file_name == "reg.exe" and
 process.args : ("save", "export") and
 process.args : ("hklm\\sam", "hklm\\security")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: Security Account Manager
    * ID: T1003.002
    * Reference URL: [https://attack.mitre.org/techniques/T1003/002/](https://attack.mitre.org/techniques/T1003/002/)

* Sub-technique:

    * Name: LSA Secrets
    * ID: T1003.004
    * Reference URL: [https://attack.mitre.org/techniques/T1003/004/](https://attack.mitre.org/techniques/T1003/004/)



