---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-powershell-pass-the-hash-relay-script.html
---

# Potential PowerShell Pass-the-Hash/Relay Script [potential-powershell-pass-the-hash-relay-script]

Detects PowerShell scripts that can execute pass-the-hash (PtH) attacks, intercept and relay NTLM challenges, and carry out other man-in-the-middle (MitM) attacks.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.powershell*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-WMIExec.ps1](https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-WMIExec.ps1)
* [https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1](https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1)
* [https://github.com/dafthack/Check-LocalAdminHash/blob/master/Check-LocalAdminHash.ps1](https://github.com/dafthack/Check-LocalAdminHash/blob/master/Check-LocalAdminHash.ps1)
* [https://github.com/nettitude/PoshC2/blob/master/resources/modules/Invoke-Tater.ps1](https://github.com/nettitude/PoshC2/blob/master/resources/modules/Invoke-Tater.ps1)
* [https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1](https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Resources: Investigation Guide
* Data Source: PowerShell Logs

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_729]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential PowerShell Pass-the-Hash/Relay Script**

PowerShell is a powerful scripting language used for task automation and configuration management in Windows environments. Adversaries exploit PowerShell to perform pass-the-hash attacks, where they use stolen hashed credentials to authenticate without knowing the actual password. The detection rule identifies scripts attempting to execute such attacks by monitoring for specific NTLM negotiation patterns and hex sequences indicative of credential relay activities, while excluding legitimate system processes.

**Possible investigation steps**

* Review the PowerShell script block text associated with the alert to identify any suspicious patterns or hex sequences, such as "NTLMSSPNegotiate" or specific hex values like "4E544C4D53535000".
* Check the process execution details, including the parent process and command line arguments, to determine if the script was executed by a legitimate user or process.
* Investigate the source and destination IP addresses involved in the NTLM negotiation to identify any unusual or unauthorized network activity.
* Examine the user account associated with the process to verify if it has been compromised or if there are any signs of unauthorized access.
* Correlate the alert with other security events or logs, such as Windows Event Logs or network traffic logs, to gather additional context and identify potential lateral movement or further compromise.
* Assess the file directory from which the script was executed, ensuring it is not a known safe location like "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads", which is excluded in the query.

**False positive analysis**

* Legitimate system processes may occasionally trigger the rule if they perform operations that mimic NTLM negotiation patterns. To manage this, users can create exceptions for specific processes known to be safe by excluding their file paths or hashes.
* Security tools or network monitoring solutions that perform NTLM authentication checks might generate false positives. Users should identify these tools and exclude their associated scripts or directories from the detection rule.
* Automated scripts for system administration that involve NTLM authentication could be flagged. Review these scripts and, if verified as safe, add them to an exclusion list based on their directory or script block text.
* PowerShell scripts used for legitimate penetration testing or security assessments may trigger alerts. Ensure these activities are documented and exclude the relevant scripts or directories during the testing period.
* Regular updates or patches from Microsoft might include scripts that temporarily match the detection criteria. Monitor updates and adjust exclusions as necessary to prevent false positives from these legitimate updates.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further credential relay or unauthorized access.
* Terminate any suspicious PowerShell processes identified by the detection rule to halt ongoing malicious activities.
* Conduct a thorough review of recent authentication logs and network traffic from the isolated system to identify any lateral movement or additional compromised accounts.
* Reset passwords for any accounts suspected to be compromised, ensuring that new credentials are not reused or easily guessable.
* Apply patches and updates to the affected system and any other vulnerable systems to mitigate known exploits used in pass-the-hash attacks.
* Implement network segmentation to limit the spread of similar attacks in the future, focusing on restricting access to critical systems and sensitive data.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_464]

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


## Rule query [_rule_query_776]

```js
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    ("NTLMSSPNegotiate" and ("NegotiateSMB" or "NegotiateSMB2")) or
    "4E544C4D53535000" or
    "0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50" or
    "0x4e,0x54,0x20,0x4c,0x4d" or
    "0x53,0x4d,0x42,0x20,0x32" or
    "0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38"
  ) and
  not file.directory : "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Adversary-in-the-Middle
    * ID: T1557
    * Reference URL: [https://attack.mitre.org/techniques/T1557/](https://attack.mitre.org/techniques/T1557/)

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

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Use Alternate Authentication Material
    * ID: T1550
    * Reference URL: [https://attack.mitre.org/techniques/T1550/](https://attack.mitre.org/techniques/T1550/)

* Sub-technique:

    * Name: Pass the Hash
    * ID: T1550.002
    * Reference URL: [https://attack.mitre.org/techniques/T1550/002/](https://attack.mitre.org/techniques/T1550/002/)



