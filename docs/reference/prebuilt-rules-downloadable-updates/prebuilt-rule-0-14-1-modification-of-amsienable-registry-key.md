---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-1-modification-of-amsienable-registry-key.html
---

# Modification of AmsiEnable Registry Key [prebuilt-rule-0-14-1-modification-of-amsienable-registry-key]

JScript tries to query the AmsiEnable registry key from the HKEY_USERS registry hive before initializing Antimalware Scan Interface (AMSI). If this key is set to 0, AMSI is not enabled for the JScript process. An adversary can modify this key to disable AMSI protections.

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

* [https://hackinparis.com/data/slides/2019/talks/HIP2019-Dominic_Chell-Cracking_The_Perimeter_With_Sharpshooter.pdf](https://hackinparis.com/data/slides/2019/talks/HIP2019-Dominic_Chell-Cracking_The_Perimeter_With_Sharpshooter.pdf)
* [https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1368]

```js
registry where event.type in ("creation", "change") and
  registry.path: "HKEY_USERS\\*\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable" and
  registry.data.strings: "0"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



