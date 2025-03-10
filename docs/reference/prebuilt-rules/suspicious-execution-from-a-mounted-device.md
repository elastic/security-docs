---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-execution-from-a-mounted-device.html
---

# Suspicious Execution from a Mounted Device [suspicious-execution-from-a-mounted-device]

Identifies when a script interpreter or signed binary is launched via a non-standard working directory. An attacker may use this technique to evade defenses.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/](https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/)
* [https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/](https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Execution
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_984]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Execution from a Mounted Device**

In Windows environments, script interpreters and signed binaries are essential for executing legitimate tasks. However, adversaries can exploit these by launching them from non-standard directories, such as mounted devices, to bypass security measures. The detection rule identifies such anomalies by monitoring processes initiated from unexpected directories, especially when triggered by common parent processes like explorer.exe, thus flagging potential defense evasion attempts.

**Possible investigation steps**

* Review the process details to confirm the executable path and working directory, ensuring they match the criteria of being launched from a non-standard directory (e.g., not from "C:\\").
* Investigate the parent process, explorer.exe, to determine if there are any unusual activities or user actions that might have triggered the suspicious execution.
* Check the user account associated with the process to verify if the activity aligns with their typical behavior or if the account might be compromised.
* Analyze the command line arguments used by the suspicious process to identify any potentially malicious scripts or commands being executed.
* Correlate the event with other security alerts or logs from the same host to identify any patterns or additional indicators of compromise.
* Examine the mounted device from which the process was executed to determine its origin, legitimacy, and any associated files that might be malicious.

**False positive analysis**

* Legitimate software installations or updates may trigger the rule if they are executed from a mounted device. Users can create exceptions for known software update processes that are verified as safe.
* Portable applications running from USB drives or external storage can be flagged. To mitigate this, users should whitelist specific applications that are frequently used and deemed non-threatening.
* IT administrative scripts executed from network shares or mounted drives for maintenance tasks might be detected. Users can exclude these scripts by specifying trusted network paths or script names.
* Development environments where scripts are tested from non-standard directories can cause alerts. Developers should ensure their working directories are recognized as safe or use designated development machines with adjusted monitoring rules.
* Backup or recovery operations that utilize mounted devices for script execution may be misidentified. Users should identify and exclude these operations by defining exceptions for known backup tools and processes.

**Response and remediation**

* Isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes identified by the detection rule, such as those initiated by script interpreters or signed binaries from non-standard directories.
* Conduct a forensic analysis of the mounted device and the affected system to identify any malicious payloads or scripts and remove them.
* Review and restore any altered system configurations or registry settings to their original state to ensure system integrity.
* Update and patch the system to close any vulnerabilities that may have been exploited by the attacker.
* Monitor for any recurrence of similar activities by enhancing logging and alerting mechanisms, focusing on process execution from non-standard directories.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_625]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_1032]

```js
process where host.os.type == "windows" and event.type == "start" and process.executable : "C:\\*" and
  (process.working_directory : "?:\\" and not process.working_directory: "C:\\") and
  process.parent.name : "explorer.exe" and
  process.name : ("rundll32.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "regsvr32.exe",
                  "cscript.exe", "wscript.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Mshta
    * ID: T1218.005
    * Reference URL: [https://attack.mitre.org/techniques/T1218/005/](https://attack.mitre.org/techniques/T1218/005/)

* Sub-technique:

    * Name: Regsvr32
    * ID: T1218.010
    * Reference URL: [https://attack.mitre.org/techniques/T1218/010/](https://attack.mitre.org/techniques/T1218/010/)

* Sub-technique:

    * Name: Rundll32
    * ID: T1218.011
    * Reference URL: [https://attack.mitre.org/techniques/T1218/011/](https://attack.mitre.org/techniques/T1218/011/)

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

* Sub-technique:

    * Name: Windows Command Shell
    * ID: T1059.003
    * Reference URL: [https://attack.mitre.org/techniques/T1059/003/](https://attack.mitre.org/techniques/T1059/003/)



