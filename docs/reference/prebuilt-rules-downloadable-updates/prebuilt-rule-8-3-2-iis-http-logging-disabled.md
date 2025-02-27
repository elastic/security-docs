---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-iis-http-logging-disabled.html
---

# IIS HTTP Logging Disabled [prebuilt-rule-8-3-2-iis-http-logging-disabled]

Identifies when Internet Information Services (IIS) HTTP Logging is disabled on a server. An attacker with IIS server access via a webshell or other mechanism can disable HTTP Logging as an effective anti-forensics measure.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 33

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2456]



## Rule query [_rule_query_2823]

```js
process where event.type == "start" and
  (process.name : "appcmd.exe" or process.pe.original_file_name == "appcmd.exe") and
  process.args : "/dontLog*:*True" and
  not process.parent.name : "iissetup.exe"
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

    * Name: Disable Windows Event Logging
    * ID: T1562.002
    * Reference URL: [https://attack.mitre.org/techniques/T1562/002/](https://attack.mitre.org/techniques/T1562/002/)



