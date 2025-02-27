---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-powershell-suspicious-script-with-audio-capture-capabilities.html
---

# PowerShell Suspicious Script with Audio Capture Capabilities [prebuilt-rule-1-0-2-powershell-suspicious-script-with-audio-capture-capabilities]

Detects PowerShell scripts that can record audio, a common feature in popular post-exploitation tooling.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-MicrophoneAudio.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-MicrophoneAudio.ps1)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Collection

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1492]

## Triage and analysis.

## Investigating PowerShell Suspicious Script with Audio Capture Capabilities

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks. This
makes it available for use in various environments, and creates an attractive way for attackers to execute code.

Attackers can use PowerShell to interact with the Windows API with the intent of capturing audio from input devices
connected to the victim's computer.

### Possible investigation steps

- Examine script content that triggered the detection.
- Investigate the script execution chain (parent process tree).
- Inspect any file or network events from the suspicious PowerShell host process instance.
- Investigate other alerts related to the user/host in the last 48 hours.
- Consider whether the user needs PowerShell to complete its tasks.
- Investigate if the script stores the recorded data locally and determine if anything was recorded.
- Investigate if the script contains exfiltration capabilities and the destination of this exfiltration.
- Assess network data to determine if the host communicated with the exfiltration server.
- Determine if the user credentials were compromised and if the attacker used them to perform unauthorized access to the
linked email account.

## False positive analysis

- Regular users should not need scripts to capture audio, which makes false positives unlikely. In the case of
authorized benign true positives (B-TPs), exceptions can be added.

## Related rules

- PowerShell PSReflect Script - 56f2e9b5-4803-4e44-a0a4-a52dc79d57fe
- Potential Process Injection via PowerShell - 2e29e96a-b67c-455a-afe4-de6183431d0d

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- The response must be prioritized if this alert involves key executives or potentially valuable targets for espionage.
- Quarantine the involved host for forensic investigation, as well as eradication and recovery activities.
- Configure AppLocker or equivalent software to restrict access to PowerShell for regular users.
- Review GPOs to add additional restrictions for PowerShell usage by users.

## Config

The 'PowerShell Script Block Logging' logging policy must be enabled.
Steps to implement the logging policy with with Advanced Audit Configuration:

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

## Rule query [_rule_query_1726]

```js
event.category:process and
  powershell.file.script_block_text : (
    "Get-MicrophoneAudio" or (waveInGetNumDevs and mciSendStringA)
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Audio Capture
    * ID: T1123
    * Reference URL: [https://attack.mitre.org/techniques/T1123/](https://attack.mitre.org/techniques/T1123/)

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



