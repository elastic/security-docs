---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-powershell-suspicious-script-with-audio-capture-capabilities.html
---

# PowerShell Suspicious Script with Audio Capture Capabilities [prebuilt-rule-0-14-3-powershell-suspicious-script-with-audio-capture-capabilities]

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

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1501]

```js
event.category:process and
  powershell.file.script_block_text : (
    Get-MicrophoneAudio or (waveInGetNumDevs and mciSendStringA)
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



