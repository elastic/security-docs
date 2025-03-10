---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/powershell-script-with-windows-defender-tampering-capabilities.html
---

# PowerShell Script with Windows Defender Tampering Capabilities [powershell-script-with-windows-defender-tampering-capabilities]

Identifies PowerShell scripts containing cmdlets and parameters that attackers can abuse to disable Windows Defender features. Attackers can tamper with antivirus to reduce the risk of detection when executing their payloads.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.powershell*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: PowerShell Logs
* Rule Type: BBR

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Setup [_setup_526]

**Setup**

The *PowerShell Script Block Logging* logging policy must be enabled. Steps to implement the logging policy with Advanced Audit Configuration:

```
Computer Configuration >
Administrative Templates >
Windows PowerShell >
Turn on PowerShell Script Block Logging (Enable)
```

Steps to implement the logging policy via registry:

```
reg add "hklm\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1
```


## Rule query [_rule_query_861]

```js
event.category: "process" and host.os.type:windows and
(
  powershell.file.script_block_text: "Set-MpPreference" and
  powershell.file.script_block_text: (
    DisableArchiveScanning or DisableBehaviorMonitoring or
    DisableIntrusionPreventionSystem or DisableIOAVProtection or
    DisableRemovableDriveScanning or DisableBlockAtFirstSeen or
    DisableScanningMappedNetworkDrivesForFullScan or
    DisableScanningNetworkFiles or DisableScriptScanning or
    DisableRealtimeMonitoring or LowThreatDefaultAction or
    ModerateThreatDefaultAction or HighThreatDefaultAction
  )
) and
not powershell.file.script_block_text : (
  ("cmdletization" and "cdxml-Help.xml") or
  ("function Set-MpPreference" and "Microsoft.PowerShell.Cmdletization.GeneratedTypes.MpPreference.SubmitSamplesConsentType")
) and
not file.directory : "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\SenseCM"
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

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: PowerShell
    * ID: T1059.001
    * Reference URL: [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)



