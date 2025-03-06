---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-microsoft-build-engine-started-by-an-office-application.html
---

# Microsoft Build Engine Started by an Office Application [prebuilt-rule-0-14-2-microsoft-build-engine-started-by-an-office-application]

An instance of MSBuild, the Microsoft Build Engine, was started by Excel or Word. This is unusual behavior for the Build Engine and could have been caused by an Excel or Word document executing a malicious script payload.

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

* [https://blog.talosintelligence.com/2020/02/building-bypass-with-msbuild.html](https://blog.talosintelligence.com/2020/02/building-bypass-with-msbuild.html)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1434]

```js
process where event.type in ("start", "process_started") and
  process.name : "MSBuild.exe" and
  process.parent.name : ("eqnedt32.exe",
                         "excel.exe",
                         "fltldr.exe",
                         "msaccess.exe",
                         "mspub.exe",
                         "outlook.exe",
                         "powerpnt.exe",
                         "winword.exe" )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Trusted Developer Utilities Proxy Execution
    * ID: T1127
    * Reference URL: [https://attack.mitre.org/techniques/T1127/](https://attack.mitre.org/techniques/T1127/)

* Sub-technique:

    * Name: MSBuild
    * ID: T1127.001
    * Reference URL: [https://attack.mitre.org/techniques/T1127/001/](https://attack.mitre.org/techniques/T1127/001/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)



