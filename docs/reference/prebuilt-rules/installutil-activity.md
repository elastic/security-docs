---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/installutil-activity.html
---

# InstallUtil Activity [installutil-activity]

InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries. Adversaries may use InstallUtil to proxy the execution of code through a trusted Windows utility.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-system.security*
* winlogbeat-*
* logs-windows.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Rule Type: BBR
* Data Source: Elastic Endgame
* Data Source: System

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_468]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.name : "installutil.exe" and not user.id : "S-1-5-18"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: InstallUtil
    * ID: T1218.004
    * Reference URL: [https://attack.mitre.org/techniques/T1218/004/](https://attack.mitre.org/techniques/T1218/004/)



