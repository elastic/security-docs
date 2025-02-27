---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-veeam-backup-library-loaded-by-unusual-process.html
---

# Veeam Backup Library Loaded by Unusual Process [prebuilt-rule-8-17-4-veeam-backup-library-loaded-by-unusual-process]

Identifies potential credential decrypt operations by PowerShell or unsigned processes using the Veeam.Backup.Common.dll library. Attackers can use Veeam Credentials to target backups as part of destructive operations such as Ransomware attacks.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.library-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4742]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Veeam Backup Library Loaded by Unusual Process**

Veeam Backup software is crucial for data protection, enabling secure backup and recovery operations. However, adversaries may exploit its credential storage by loading the Veeam.Backup.Common.dll library through unauthorized processes like PowerShell, aiming to decrypt and misuse credentials. The detection rule identifies such anomalies by flagging untrusted or unsigned processes loading this library, indicating potential credential access attempts.

**Possible investigation steps**

* Review the process details to identify the untrusted or unsigned process that loaded the Veeam.Backup.Common.dll library, focusing on the process.name field to determine if it is PowerShell or another suspicious executable.
* Check the process execution history and command line arguments to understand the context of the process activity, especially if the process.name is powershell.exe, pwsh.exe, or powershell_ise.exe.
* Investigate the source and integrity of the process by examining the process.code_signature fields to determine if the process is expected or potentially malicious.
* Analyze the timeline of events on the host to identify any preceding or subsequent suspicious activities that might indicate a broader attack pattern or lateral movement.
* Correlate the alert with other security events or logs from the same host or network to identify any related indicators of compromise or additional affected systems.

**False positive analysis**

* Legitimate administrative scripts or automation tasks using PowerShell may trigger the rule. Review the script’s purpose and source, and if verified as safe, consider adding an exception for the specific script or process.
* Scheduled tasks or maintenance operations that involve Veeam Backup operations might load the library through unsigned processes. Validate these tasks and exclude them if they are part of routine, secure operations.
* Custom or third-party backup solutions that integrate with Veeam may load the library in a non-standard way. Confirm the legitimacy of these solutions and whitelist them to prevent unnecessary alerts.
* Development or testing environments where Veeam components are frequently loaded by various processes for testing purposes can generate false positives. Implement process exclusions for these environments to reduce noise.
* Ensure that any exclusions or exceptions are documented and reviewed regularly to maintain security posture and adapt to any changes in the environment.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified as loading the Veeam.Backup.Common.dll library, especially those that are unsigned or involve PowerShell.
* Conduct a thorough review of the system’s event logs and process history to identify any additional unauthorized access or actions taken by the adversary.
* Change all credentials stored within the Veeam Backup software and any other potentially compromised accounts to prevent misuse.
* Restore any affected systems or data from a known good backup to ensure integrity and availability.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and alerting for similar activities, focusing on unauthorized process executions and DLL loads, to improve early detection of future threats.


## Rule query [_rule_query_5697]

```js
library where host.os.type == "windows" and event.action == "load" and
  (dll.name : "Veeam.Backup.Common.dll" or dll.pe.original_file_name : "Veeam.Backup.Common.dll") and
  (
    process.code_signature.trusted == false or
    process.code_signature.exists == false or
    process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
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

    * Name: Credentials from Password Stores
    * ID: T1555
    * Reference URL: [https://attack.mitre.org/techniques/T1555/](https://attack.mitre.org/techniques/T1555/)

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



