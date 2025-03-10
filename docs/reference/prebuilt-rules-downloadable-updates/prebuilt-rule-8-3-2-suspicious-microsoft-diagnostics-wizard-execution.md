---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-suspicious-microsoft-diagnostics-wizard-execution.html
---

# Suspicious Microsoft Diagnostics Wizard Execution [prebuilt-rule-8-3-2-suspicious-microsoft-diagnostics-wizard-execution]

Identifies potential abuse of the Microsoft Diagnostics Troubleshooting Wizard (MSDT) to proxy malicious command or binary execution via malicious process arguments.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://twitter.com/nao_sec/status/1530196847679401984](https://twitter.com/nao_sec/status/1530196847679401984)
* [https://lolbas-project.github.io/lolbas/Binaries/Msdt/](https://lolbas-project.github.io/lolbas/Binaries/Msdt/)

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

## Investigation guide [_investigation_guide_2466]



## Rule query [_rule_query_2836]

```js
process where event.type == "start" and
   (process.pe.original_file_name == "msdt.exe" or process.name : "msdt.exe") and
   (
    process.args : ("IT_RebrowseForFile=*", "ms-msdt:/id", "ms-msdt:-id", "*FromBase64*") or

    (process.args : "-af" and process.args : "/skip" and
     process.parent.name : ("explorer.exe", "cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe") and
     process.args : ("?:\\WINDOWS\\diagnostics\\index\\PCWDiagnostic.xml", "PCWDiagnostic.xml", "?:\\Users\\Public\\*", "?:\\Windows\\Temp\\*")) or

    (process.pe.original_file_name == "msdt.exe" and not process.name : "msdt.exe" and process.name != null) or

    (process.pe.original_file_name == "msdt.exe" and not process.executable : ("?:\\Windows\\system32\\msdt.exe", "?:\\Windows\\SysWOW64\\msdt.exe"))
    )
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



