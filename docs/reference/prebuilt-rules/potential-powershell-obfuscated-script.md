---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-powershell-obfuscated-script.html
---

# Potential PowerShell Obfuscated Script [potential-powershell-obfuscated-script]

Identifies scripts that contain patterns and known methods that obfuscate PowerShell code. Attackers can use obfuscation techniques to bypass PowerShell security protections such as Antimalware Scan Interface (AMSI).

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

* [https://github.com/danielbohannon/Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: PowerShell Logs
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_728]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential PowerShell Obfuscated Script**

PowerShell is a powerful scripting language used for task automation and configuration management in Windows environments. Adversaries exploit its flexibility to obfuscate scripts, evading security measures like AMSI. The detection rule identifies obfuscation patterns, such as string manipulation and encoding techniques, to flag potentially malicious scripts, aiding in defense evasion detection.

**Possible investigation steps**

* Review the PowerShell script block text captured in the alert to identify any suspicious patterns or obfuscation techniques, such as string manipulation or encoding methods like "[string]::join" or "-Join".
* Check the process execution details, including the parent process and command line arguments, to understand the context in which the PowerShell script was executed.
* Investigate the source and destination of the script execution by examining the host and user details to determine if the activity aligns with expected behavior or if it originates from an unusual or unauthorized source.
* Analyze any network connections or file modifications associated with the PowerShell process to identify potential data exfiltration or lateral movement activities.
* Correlate the alert with other security events or logs, such as Windows Event Logs or network traffic logs, to gather additional context and identify any related suspicious activities.
* Assess the risk and impact of the detected activity by considering the severity and risk score provided in the alert, and determine if immediate remediation actions are necessary.

**False positive analysis**

* Legitimate administrative scripts may use string manipulation and encoding techniques for benign purposes, such as data processing or configuration management. Review the context of the script execution and verify the source and intent before flagging it as malicious.
* Scripts that automate complex tasks might use obfuscation-like patterns to handle data securely or efficiently. Consider whitelisting known scripts or trusted sources to reduce false positives.
* Development and testing environments often run scripts with obfuscation patterns for testing purposes. Exclude these environments from the rule or create exceptions for specific users or groups involved in development.
* Security tools and monitoring solutions might generate PowerShell scripts with obfuscation patterns as part of their normal operation. Identify these tools and exclude their activities from triggering the rule.
* Regularly update the list of exceptions and whitelisted scripts to ensure that new legitimate scripts are not mistakenly flagged as threats.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of potentially malicious scripts.
* Terminate any suspicious PowerShell processes identified by the detection rule to halt ongoing malicious activity.
* Conduct a thorough review of the PowerShell script block logs to identify and remove any obfuscated scripts or malicious code remnants.
* Restore the system from a known good backup if malicious activity is confirmed and system integrity is compromised.
* Update and patch the affected system to ensure all security vulnerabilities are addressed, reducing the risk of exploitation.
* Monitor the system and network for any signs of re-infection or similar obfuscation patterns to ensure the threat has been fully mitigated.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.


## Setup [_setup_463]

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


## Rule query [_rule_query_775]

```js
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "[string]::join" or
    "-Join" or
    "[convert]::toint16" or
    "[char][int]$_" or
    ("ConvertTo-SecureString" and "PtrToStringAuto") or
    ".GetNetworkCredential().password" or
    "-BXor" or
    ("replace" and "char") or
    "[array]::reverse" or
    "-replace"
  ) and
  powershell.file.script_block_text : (
    ("$pSHoMe[" and "+$pSHoMe[") or
    ("$ShellId[" and "+$ShellId[") or
    ("$env:ComSpec[4" and "25]-Join") or
    (("Set-Variable" or "SV" or "Set-Item") and "OFS") or
    ("*MDR*" and "Name[3,11,2]") or
    ("$VerbosePreference" and "[1,3]+'X'-Join''") or
    ("rahc" or "ekovin" or "gnirts" or "ecnereferpesobrev" or "ecalper" or "cepsmoc" or "dillehs") or
    ("System.Management.Automation.$([cHAr]" or "System.$([cHAr]" or ")+[cHAR]([byte]")
  )
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

* Technique:

    * Name: Deobfuscate/Decode Files or Information
    * ID: T1140
    * Reference URL: [https://attack.mitre.org/techniques/T1140/](https://attack.mitre.org/techniques/T1140/)

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



