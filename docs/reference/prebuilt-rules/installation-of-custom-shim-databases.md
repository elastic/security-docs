---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/installation-of-custom-shim-databases.html
---

# Installation of Custom Shim Databases [installation-of-custom-shim-databases]

Identifies the installation of custom Application Compatibility Shim databases. This Windows functionality has been abused by attackers to stealthily gain persistence and arbitrary code execution in legitimate Windows processes.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* winlogbeat-*
* logs-windows.sysmon_operational-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* endgame-*

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
* Tactic: Persistence
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 310

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_435]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Installation of Custom Shim Databases**

Application Compatibility Shim databases are used in Windows to ensure older applications run smoothly on newer OS versions by applying compatibility fixes. However, attackers can exploit this feature to maintain persistence and execute arbitrary code by installing malicious shim databases. The detection rule identifies changes in specific registry paths associated with these databases, excluding known legitimate processes, to flag potential abuse.

**Possible investigation steps**

* Review the registry path changes identified in the alert to confirm the presence of any unexpected or unauthorized .sdb files in the specified registry paths.
* Investigate the process that made the registry change by examining the process executable path and comparing it against the list of known legitimate processes excluded in the query.
* Check the historical activity of the process responsible for the change to identify any patterns or anomalies that might indicate malicious behavior.
* Analyze the context around the time of the registry change, including other system events or alerts, to identify any related suspicious activities.
* If a suspicious .sdb file is found, conduct a file analysis to determine its purpose and whether it contains any malicious code or configurations.
* Consult threat intelligence sources to see if there are any known threats or campaigns associated with the identified process or .sdb file.

**False positive analysis**

* Known legitimate processes such as SAP and Kaspersky applications may trigger false positives due to their use of shim databases. These processes are already excluded in the detection rule to minimize unnecessary alerts.
* If additional legitimate applications are identified as causing false positives, users can update the exclusion list by adding the specific process executable paths to the rule.
* Regularly review and update the exclusion list to ensure it reflects the current environment and any new legitimate applications that may use shim databases.
* Monitor the frequency and context of alerts to distinguish between benign and potentially malicious activities, adjusting the rule as necessary to reduce noise.
* Engage with application owners to verify the legitimacy of processes that frequently trigger alerts, ensuring that only trusted applications are excluded.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further propagation or communication with potential command and control servers.
* Terminate any suspicious processes identified as responsible for the installation of the custom shim database, ensuring they are not legitimate processes mistakenly flagged.
* Remove the malicious shim database entries from the registry paths specified in the detection query to eliminate persistence mechanisms.
* Conduct a thorough scan of the affected system using updated antivirus and endpoint detection tools to identify and remove any additional malware or unauthorized changes.
* Review and restore any altered system configurations or files to their original state to ensure system integrity.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for the specified registry paths and associated processes to detect and respond to similar threats in the future.


## Rule query [_rule_query_470]

```js
registry where host.os.type == "windows" and event.type == "change" and
    registry.path : (
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\*.sdb",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\*.sdb",
        "MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\*.sdb"
    ) and
    not process.executable :
                       ("?:\\Program Files (x86)\\DesktopCentral_Agent\\swrepository\\1\\swuploads\\SAP-SLC\\SAPSetupSLC02_14-80001954\\Setup\\NwSapSetup.exe",
                        "?:\\$WINDOWS.~BT\\Sources\\SetupPlatform.exe",
                         "?:\\Program Files (x86)\\SAP\\SAPsetup\\setup\\NwSapSetup.exe",
                         "?:\\Program Files (x86)\\SAP\\SapSetup\\OnRebootSvc\\NWSAPSetupOnRebootInstSvc.exe",
                         "?:\\Program Files (x86)\\Kaspersky Lab\\Kaspersky Security for Windows Server\\kavfs.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Application Shimming
    * ID: T1546.011
    * Reference URL: [https://attack.mitre.org/techniques/T1546/011/](https://attack.mitre.org/techniques/T1546/011/)



