---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-powershell-script-with-webcam-video-capture-capabilities.html
---

# PowerShell Script with Webcam Video Capture Capabilities [prebuilt-rule-8-17-4-powershell-script-with-webcam-video-capture-capabilities]

Detects PowerShell scripts that can be used to record webcam video. Attackers can capture this information to extort or spy on victims.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.powershell*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/collection/WebcamRecorder.py](https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/collection/WebcamRecorder.py)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Collection
* Data Source: PowerShell Logs
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4685]

**Triage and analysis**

[TBC: QUOTE]
**Investigating PowerShell Script with Webcam Video Capture Capabilities**

PowerShell, a powerful scripting language in Windows, can interface with system components like webcams for legitimate tasks such as video conferencing. However, adversaries exploit this by crafting scripts to covertly record video, infringing on privacy. The detection rule identifies suspicious script patterns and API calls linked to webcam access, flagging potential misuse for further investigation.

**Possible investigation steps**

* Review the PowerShell script block text associated with the alert to identify any suspicious patterns or API calls, such as "NewFrameEventHandler" or "VideoCaptureDevice".
* Check the process execution details, including the parent process, to determine how the PowerShell script was initiated and if it was part of a legitimate application or task.
* Investigate the user account under which the PowerShell script was executed to assess if the account has a history of suspicious activity or if it has been compromised.
* Examine the host’s recent activity logs for any other unusual behavior or alerts that might correlate with the webcam access attempt, such as unauthorized access attempts or data exfiltration.
* Verify if the host has any legitimate applications that might use webcam access, and cross-reference with the script’s behavior to rule out false positives.

**False positive analysis**

* Legitimate video conferencing applications may trigger the detection rule due to their use of similar API calls and script patterns. Users can create exceptions for known and trusted applications by whitelisting their process names or script signatures.
* Security testing tools that simulate webcam access for vulnerability assessments might be flagged. To handle this, users should exclude these tools from monitoring during scheduled testing periods.
* System diagnostics or maintenance scripts that access webcam components for hardware checks can be mistaken for malicious activity. Users should document and exclude these scripts if they are part of routine system operations.
* Educational or training software that uses webcam access for interactive sessions may be incorrectly identified. Users can mitigate this by adding these applications to an allowlist after verifying their legitimacy.
* Custom scripts developed in-house for specific business needs that involve webcam access should be reviewed and, if deemed safe, excluded from the detection rule to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious PowerShell processes identified by the detection rule to stop ongoing webcam recording activities.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any malicious scripts or software.
* Review and revoke any unauthorized access permissions or credentials that may have been compromised during the incident.
* Restore the system from a known good backup if any critical system files or configurations have been altered by the malicious script.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for PowerShell activities across the network to detect and respond to similar threats more effectively in the future.


## Setup [_setup_1499]

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


## Rule query [_rule_query_5640]

```js
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "NewFrameEventHandler" or
    "VideoCaptureDevice" or
    "DirectX.Capture.Filters" or
    "VideoCompressors" or
    "Start-WebcamRecorder" or
    (
      ("capCreateCaptureWindowA" or
       "capCreateCaptureWindow" or
       "capGetDriverDescription") and
      ("avicap32.dll" or "avicap32")
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Video Capture
    * ID: T1125
    * Reference URL: [https://attack.mitre.org/techniques/T1125/](https://attack.mitre.org/techniques/T1125/)

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



