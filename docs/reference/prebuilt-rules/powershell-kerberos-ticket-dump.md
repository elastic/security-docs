---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/powershell-kerberos-ticket-dump.html
---

# PowerShell Kerberos Ticket Dump [powershell-kerberos-ticket-dump]

Detects PowerShell scripts that have the capability of dumping Kerberos tickets from LSA, which potentially indicates an attacker’s attempt to acquire credentials for lateral movement.

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

* [https://github.com/MzHmO/PowershellKerberos/blob/main/dumper.ps1](https://github.com/MzHmO/PowershellKerberos/blob/main/dumper.ps1)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: PowerShell Logs
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_797]

**Triage and analysis**

**Investigating PowerShell Kerberos Ticket Dump**

Kerberos is an authentication protocol that relies on tickets to grant access to network resources. Adversaries may abuse this protocol to acquire credentials for lateral movement within a network.

This rule indicates the use of scripts that contain code capable of dumping Kerberos tickets, which can indicate potential PowerShell abuse for credential theft.

**Possible investigation steps**

* Examine the script content that triggered the detection; look for suspicious DLL imports, collection or exfiltration capabilities, suspicious functions, encoded or compressed data, and other potentially malicious characteristics.
* Investigate the script execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Investigate if the script was executed, and if so, which account was targeted.
* Identify the account involved and contact the owner to confirm whether they are aware of this activity.
* Check if the script has any other functionality that can be potentially malicious.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Investigate other potentially compromised accounts and hosts. Review login events (like 4624) for suspicious events involving the subject and target accounts.

**False positive analysis**

* If this activity is expected and noisy in your environment, consider adding exceptions — preferably with a combination of file path and user ID conditions.

**Related Rules**

* PowerShell Kerberos Ticket Request - eb610e70-f9e6-4949-82b9-f1c5bcd37c39

**Response and Remediation**

* Initiate the incident response process based on the outcome of the triage.
* If malicious activity is confirmed, perform a broader investigation to identify the scope of the compromise and determine the appropriate remediation steps.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Disable or limit involved accounts during the investigation and response.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Reimage the host operating system or restore the compromised files to clean versions.
* Restrict PowerShell usage outside of IT and engineering business units using GPOs, AppLocker, Intune, or similar software.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_512]

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


## Rule query [_rule_query_845]

```js
event.category:process and host.os.type:windows and
  powershell.file.script_block_text : (
    "LsaCallAuthenticationPackage" and
    (
      "KerbRetrieveEncodedTicketMessage" or
      "KerbQueryTicketCacheMessage" or
      "KerbQueryTicketCacheExMessage" or
      "KerbQueryTicketCacheEx2Message" or
      "KerbRetrieveTicketMessage" or
      "KerbDecryptDataMessage"
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Technique:

    * Name: Steal or Forge Kerberos Tickets
    * ID: T1558
    * Reference URL: [https://attack.mitre.org/techniques/T1558/](https://attack.mitre.org/techniques/T1558/)

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



