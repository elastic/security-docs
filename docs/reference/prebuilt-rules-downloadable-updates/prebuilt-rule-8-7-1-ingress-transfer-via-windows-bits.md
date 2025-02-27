---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-ingress-transfer-via-windows-bits.html
---

# Ingress Transfer via Windows BITS [prebuilt-rule-8-7-1-ingress-transfer-via-windows-bits]

Identifies downloads of executable and archive files via the Windows Background Intelligent Transfer Service (BITS). Adversaries could leverage Windows BITS transfer jobs to download remote payloads.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://attack.mitre.org/techniques/T1197/](https://attack.mitre.org/techniques/T1197/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion
* Command and Control

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4655]

```js
file where event.action == "rename" and

process.name : "svchost.exe" and file.Ext.original.name : "BIT*.tmp" and
 (file.extension :("exe", "zip", "rar", "bat", "dll", "ps1", "vbs", "wsh", "js", "vbe", "pif", "scr", "cmd", "cpl") or file.Ext.header_bytes : "4d5a*") and

 /* noisy paths, for hunting purposes you can use the same query without the following exclusions */
 not file.path : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*", "?:\\Windows\\*", "?:\\ProgramData\\*\\*") and

 /* lot of third party SW use BITS to download executables with a long file name */
 not length(file.name) > 30
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Ingress Tool Transfer
    * ID: T1105
    * Reference URL: [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: BITS Jobs
    * ID: T1197
    * Reference URL: [https://attack.mitre.org/techniques/T1197/](https://attack.mitre.org/techniques/T1197/)



