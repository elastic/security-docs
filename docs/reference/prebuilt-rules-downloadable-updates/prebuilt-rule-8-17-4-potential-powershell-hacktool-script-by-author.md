---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-powershell-hacktool-script-by-author.html
---

# Potential PowerShell HackTool Script by Author [prebuilt-rule-8-17-4-potential-powershell-hacktool-script-by-author]

Detects known PowerShell offensive tooling author’s name in PowerShell scripts. Attackers commonly use out-of-the-box offensive tools without modifying the code, which may still contain the author artifacts. This rule identifies common author handles found in popular PowerShell scripts used for red team exercises.

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

* [https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md](https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0109_windows_powershell_script_block_log.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: PowerShell Logs
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4848]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential PowerShell HackTool Script by Author**

PowerShell is a powerful scripting language and automation framework used in Windows environments for task automation and configuration management. Adversaries exploit PowerShell’s capabilities to execute malicious scripts, often leveraging well-known offensive tools without altering the original code. The detection rule identifies scripts containing specific author names linked to these tools, flagging potential misuse by recognizing unmodified author artifacts in the script block text.

**Possible investigation steps**

* Review the PowerShell script block text associated with the alert to identify the specific author name that triggered the detection. This can provide insight into the potential tool or script being used.
* Examine the process details, including the parent process and command line arguments, to understand the context in which the PowerShell script was executed. This can help determine if the execution was part of a legitimate task or a suspicious activity.
* Check the host’s recent activity logs for any other unusual or related events, such as network connections, file modifications, or other process executions, to identify potential lateral movement or data exfiltration attempts.
* Investigate the user account under which the PowerShell script was executed to determine if it has been compromised or if the activity aligns with the user’s typical behavior.
* Correlate the alert with other security tools and logs, such as antivirus or endpoint detection and response (EDR) solutions, to gather additional context and confirm whether the activity is malicious.

**False positive analysis**

* Scripts used in legitimate red team exercises may trigger the rule due to the presence of known author names. To manage this, create exceptions for scripts verified as part of authorized security assessments.
* PowerShell scripts from open-source security tools used for internal testing or training might be flagged. Ensure these tools are documented and approved, then exclude them from the rule.
* Automated scripts for system administration that include code snippets from well-known authors could be mistakenly identified. Review and whitelist these scripts if they are part of routine operations.
* Security research and development activities using sample scripts from recognized authors may cause alerts. Maintain a list of such activities and exclude them from detection to avoid unnecessary alerts.
* Internal development teams using PowerShell scripts for legitimate purposes might inadvertently use code from popular authors. Conduct regular reviews and exclude these scripts if they are deemed non-threatening.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further execution of potentially malicious scripts and lateral movement.
* Terminate any suspicious PowerShell processes identified by the alert to halt ongoing malicious activity.
* Conduct a thorough review of the PowerShell script block text to confirm the presence of known offensive tool author names and assess the potential impact.
* Remove any unauthorized or malicious scripts from the affected system and ensure that all legitimate scripts are verified and restored from a clean backup.
* Update endpoint protection and antivirus signatures to detect and block the specific PowerShell scripts and associated indicators of compromise (IOCs) identified in the alert.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for PowerShell activity across the network to detect similar threats in the future, leveraging the MITRE ATT&CK framework for guidance on relevant techniques and tactics.


## Setup [_setup_1544]

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


## Rule query [_rule_query_5803]

```js
host.os.type:windows and event.category:process and
  powershell.file.script_block_text : (
      "mattifestation" or "JosephBialek" or
      "harmj0y" or "ukstufus" or
      "SecureThisShit" or "Matthew Graeber" or
      "secabstraction" or "mgeeky" or
      "oddvarmoe" or "am0nsec" or
      "obscuresec" or "sixdub" or
      "darkoperator" or "funoverip" or
      "rvrsh3ll" or "kevin_robertson" or
      "dafthack" or "r4wd3r" or
      "danielhbohannon" or "OneLogicalMyth" or
      "cobbr_io" or "xorrior" or
      "PetrMedonos" or "citronneur" or
      "eladshamir" or "RastaMouse" or
      "enigma0x3" or "FuzzySec" or
      "424f424f" or "jaredhaight" or
      "fullmetalcache" or "Hubbl3" or
      "curi0usJack" or "Cx01N" or
      "itm4n" or "nurfed1" or
      "cfalta" or "Scott Sutherland" or
      "_nullbind" or "_tmenochet" or
      "jaredcatkinson" or "ChrisTruncer" or
      "monoxgas" or "TheRealWover" or
      "splinter_code"
  )
```

**Framework**: MITRE ATT&CKTM

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



