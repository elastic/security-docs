---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-suspicious-managed-code-hosting-process.html
---

# Suspicious Managed Code Hosting Process [prebuilt-rule-8-3-3-suspicious-managed-code-hosting-process]

Identifies a suspicious managed code hosting process which could indicate code injection or other form of suspicious code execution.

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

* [https://web.archive.org/web/20230329154538/https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html](https://web.archive.org/web/20230329154538/https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.md)

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

## Rule query [_rule_query_3596]

```js
sequence by process.entity_id with maxspan=5m
 [process where event.type == "start" and
  process.name : ("wscript.exe", "cscript.exe", "mshta.exe", "wmic.exe", "regsvr32.exe", "svchost.exe", "dllhost.exe", "cmstp.exe")]
 [file where event.type != "deletion" and
  file.name : ("wscript.exe.log",
               "cscript.exe",
               "mshta.exe.log",
               "wmic.exe.log",
               "svchost.exe.log",
               "dllhost.exe.log",
               "cmstp.exe.log",
               "regsvr32.exe.log")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)



