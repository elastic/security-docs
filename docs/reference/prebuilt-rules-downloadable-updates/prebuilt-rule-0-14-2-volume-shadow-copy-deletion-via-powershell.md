---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-volume-shadow-copy-deletion-via-powershell.html
---

# Volume Shadow Copy Deletion via PowerShell [prebuilt-rule-0-14-2-volume-shadow-copy-deletion-via-powershell]

Identifies the use of the Win32_ShadowCopy class and related cmdlets to achieve shadow copy deletion. This commonly occurs in tandem with ransomware or other destructive attacks.

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

* [https://docs.microsoft.com/en-us/previous-versions/windows/desktop/vsswmi/win32-shadowcopy](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/vsswmi/win32-shadowcopy)
* [https://powershell.one/wmi/root/cimv2/win32_shadowcopy](https://powershell.one/wmi/root/cimv2/win32_shadowcopy)
* [https://www.fortinet.com/blog/threat-research/stomping-shadow-copies-a-second-look-into-deletion-methods](https://www.fortinet.com/blog/threat-research/stomping-shadow-copies-a-second-look-into-deletion-methods)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Impact

**Version**: 1

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Rule query [_rule_query_1403]

```js
process where event.type in ("start", "process_started") and
  process.name : ("powershell.exe", "pwsh.exe") and
  process.args : ("*Get-WmiObject*", "*gwmi*", "*Get-CimInstance*", "*gcim*") and
  process.args : ("*Win32_ShadowCopy*") and
  process.args : ("*.Delete()*", "*Remove-WmiObject*", "*rwmi*", "*Remove-CimInstance*", "*rcim*")
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



