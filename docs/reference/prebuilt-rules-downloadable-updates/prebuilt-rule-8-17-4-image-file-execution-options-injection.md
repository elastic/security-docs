---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-image-file-execution-options-injection.html
---

# Image File Execution Options Injection [prebuilt-rule-8-17-4-image-file-execution-options-injection]

The Debugger and SilentProcessExit registry keys can allow an adversary to intercept the execution of files, causing a different process to be executed. This functionality can be abused by an adversary to establish persistence.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* endgame-*
* logs-windows.sysmon_operational-*
* winlogbeat-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/](https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 310

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4908]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Image File Execution Options Injection**

Image File Execution Options (IFEO) is a Windows feature allowing developers to debug applications by specifying an alternative executable to run. Adversaries exploit this by setting a debugger to execute malicious code instead, achieving persistence or evasion. The detection rule identifies changes to specific registry keys associated with IFEO, flagging potential misuse by monitoring for unexpected executables being set as debuggers.

**Possible investigation steps**

* Review the registry path and value that triggered the alert to identify the specific executable or process being targeted for debugging or monitoring.
* Check the registry.data.strings field to determine the unexpected executable set as a debugger or monitor process, and assess its legitimacy.
* Investigate the origin and purpose of the executable found in the registry.data.strings by checking its file properties, digital signature, and any associated metadata.
* Correlate the alert with recent system or user activity to identify any suspicious behavior or changes that coincide with the registry modification.
* Examine the system for additional indicators of compromise, such as unusual network connections, file modifications, or other registry changes, to assess the scope of potential malicious activity.
* Consult threat intelligence sources to determine if the identified executable or behavior is associated with known malware or threat actors.

**False positive analysis**

* ThinKiosk and PSAppDeployToolkit are known to trigger false positives due to their legitimate use of the Debugger registry key. Users can mitigate this by adding exceptions for these applications in the detection rule.
* Regularly review and update the list of exceptions to include any new legitimate applications that may use the Debugger or MonitorProcess registry keys for valid purposes.
* Monitor the environment for any new software installations or updates that might interact with the IFEO registry keys and adjust the rule exceptions accordingly to prevent unnecessary alerts.
* Collaborate with IT and security teams to identify any internal tools or scripts that might be using these registry keys for legitimate reasons and ensure they are accounted for in the rule exceptions.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further spread or communication with potential command and control servers.
* Terminate any suspicious processes identified as being executed through the IFEO mechanism to halt any ongoing malicious activity.
* Revert any unauthorized changes to the registry keys associated with Image File Execution Options and SilentProcessExit to their default or intended state.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malware or persistence mechanisms.
* Review and restore any altered or deleted system files from a known good backup to ensure system integrity.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for registry changes related to IFEO to detect and respond to similar threats in the future.


## Rule query [_rule_query_5863]

```js
registry where host.os.type == "windows" and event.type == "change" and
  registry.value : ("Debugger", "MonitorProcess") and length(registry.data.strings) > 0 and
  registry.path : (
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*.exe\\Debugger",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\Debugger",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess",
    "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess",
    "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*.exe\\Debugger",
    "\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\Debugger",
    "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess",
    "\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess",
    "MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*.exe\\Debugger",
    "MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\Debugger",
    "MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess",
    "MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*\\MonitorProcess"
  ) and
    /* add FPs here */
  not registry.data.strings regex~ ("""C:\\Program Files( \(x86\))?\\ThinKiosk\\thinkiosk\.exe""", """.*\\PSAppDeployToolkit\\.*""")
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

    * Name: Image File Execution Options Injection
    * ID: T1546.012
    * Reference URL: [https://attack.mitre.org/techniques/T1546/012/](https://attack.mitre.org/techniques/T1546/012/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)



