---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-microsoft-build-engine-started-an-unusual-process.html
---

# Microsoft Build Engine Started an Unusual Process [prebuilt-rule-8-2-1-microsoft-build-engine-started-an-unusual-process]

An instance of MSBuild, the Microsoft Build Engine, started a PowerShell script or the Visual C# Command Line Compiler. This technique is sometimes used to deploy a malicious payload using the Build Engine.

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

**References**:

* [https://blog.talosintelligence.com/2020/02/building-bypass-with-msbuild.html](https://blog.talosintelligence.com/2020/02/building-bypass-with-msbuild.html)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 11

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2118]



## Rule query [_rule_query_2408]

```js
process where event.type in ("start", "process_started") and
  process.parent.name : "MSBuild.exe" and
  process.name : ("csc.exe", "iexplore.exe", "powershell.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Obfuscated Files or Information
    * ID: T1027
    * Reference URL: [https://attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/)

* Sub-technique:

    * Name: Compile After Delivery
    * ID: T1027.004
    * Reference URL: [https://attack.mitre.org/techniques/T1027/004/](https://attack.mitre.org/techniques/T1027/004/)



