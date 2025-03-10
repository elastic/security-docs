---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-powershell-suspicious-script-with-audio-capture-capabilities.html
---

# PowerShell Suspicious Script with Audio Capture Capabilities [prebuilt-rule-8-4-1-powershell-suspicious-script-with-audio-capture-capabilities]

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
* Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2666]

## Triage and analysis

## Investigating PowerShell Suspicious Script with Audio Capture Capabilities

PowerShell is one of the main tools system administrators use for automation, report routines, and other tasks. This
makes it available for use in various environments, and creates an attractive way for attackers to execute code.

Attackers can use PowerShell to interact with the Windows API with the intent of capturing audio from input devices
connected to the victim's computer.

### Possible investigation steps

- Examine the script content that triggered the detection; look for suspicious DLL imports, collection or exfiltration
capabilities, suspicious functions, encoded or compressed data, and other potentially malicious characteristics.
- Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for
prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Examine file or network events from the involved PowerShell process for suspicious behavior.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Evaluate whether the user needs to use PowerShell to complete tasks.
- Investigate if the script stores the recorded data locally and determine if anything was recorded.
- Investigate if the script contains exfiltration capabilities and the destination of this exfiltration.
- Assess network data to determine if the host communicated with the exfiltration server.

## False positive analysis

- Regular users should not need scripts to capture audio, which makes false positives unlikely. In the case of
authorized benign true positives (B-TPs), exceptions can be added.

## Related rules

- PowerShell PSReflect Script - 56f2e9b5-4803-4e44-a0a4-a52dc79d57fe
- Potential Process Injection via PowerShell - 2e29e96a-b67c-455a-afe4-de6183431d0d

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- The response must be prioritized if this alert involves key executives or potentially valuable targets for espionage.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Restrict PowerShell usage outside of IT and engineering business units using GPOs, AppLocker, Intune, or similar software.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_3056]

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



