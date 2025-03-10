---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-execution-of-com-object-via-xwizard.html
---

# Execution of COM object via Xwizard [prebuilt-rule-8-17-4-execution-of-com-object-via-xwizard]

Windows Component Object Model (COM) is an inter-process communication (IPC) component of the native Windows application programming interface (API) that enables interaction between software objects or executable code. Xwizard can be used to run a COM object created in registry to evade defensive counter measures.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* logs-crowdstrike.fdr*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://lolbas-project.github.io/lolbas/Binaries/Xwizard/](https://lolbas-project.github.io/lolbas/Binaries/Xwizard/)
* [http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/](http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 313

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4833]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Execution of COM object via Xwizard**

The Windows Component Object Model (COM) facilitates communication between software components. Adversaries exploit this by using Xwizard to execute COM objects, bypassing security measures. The detection rule identifies suspicious Xwizard executions by monitoring process starts, checking for unusual arguments, and verifying executable paths, thus flagging potential misuse of COM objects for malicious activities.

**Possible investigation steps**

* Review the process start event details to confirm the presence of xwizard.exe execution, focusing on the process.name and process.pe.original_file_name fields.
* Examine the process.args field to identify any unusual or suspicious arguments, particularly looking for the "RunWizard" command and any GUIDs or patterns that may indicate malicious activity.
* Verify the process.executable path to ensure it matches the expected system paths (C:\Windows\SysWOW64\xwizard.exe or C:\Windows\System32\xwizard.exe). Investigate any deviations from these paths as potential indicators of compromise.
* Check the parent process of xwizard.exe to understand the context of its execution and identify any potentially malicious parent processes.
* Correlate the event with other security data sources such as Microsoft Defender for Endpoint or Sysmon logs to gather additional context and identify any related suspicious activities or patterns.
* Investigate the user account associated with the process execution to determine if it aligns with expected behavior or if it indicates potential unauthorized access or privilege escalation.

**False positive analysis**

* Legitimate software installations or updates may trigger the rule if they use Xwizard to execute COM objects. Users can create exceptions for known software update processes by verifying the executable paths and arguments.
* System administrators might use Xwizard for legitimate configuration tasks. To handle this, identify and document regular administrative activities and exclude these from the rule by specifying the expected process arguments and executable paths.
* Automated scripts or management tools that utilize Xwizard for system management tasks can cause false positives. Review and whitelist these scripts or tools by ensuring their execution paths and arguments are consistent with known safe operations.
* Some security tools or monitoring solutions might use Xwizard as part of their normal operations. Confirm these activities with the tool’s documentation and exclude them by adding their specific execution patterns to the exception list.

**Response and remediation**

* Isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious xwizard.exe processes identified by the detection rule to halt potential malicious execution.
* Conduct a thorough review of the system’s registry for unauthorized COM objects and remove any entries that are not recognized or are deemed malicious.
* Restore the system from a known good backup if unauthorized changes or persistent threats are detected.
* Update and patch the system to the latest security standards to close any vulnerabilities that may have been exploited.
* Monitor the network for any signs of similar activity or related threats, ensuring that detection systems are tuned to identify variations of this attack.
* Escalate the incident to the security operations center (SOC) or relevant security team for further analysis and to determine if additional systems are affected.


## Rule query [_rule_query_5788]

```js
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "xwizard.exe" or ?process.pe.original_file_name : "xwizard.exe") and
 (
   (process.args : "RunWizard" and process.args : "{*}") or
   (process.executable != null and
     not process.executable : (
        "C:\\Windows\\SysWOW64\\xwizard.exe",
        "C:\\Windows\\System32\\xwizard.exe",
        "\\Device\\HarddiskVolume?\\Windows\\SysWOW64\\xwizard.exe",
        "\\Device\\HarddiskVolume?\\Windows\\System32\\xwizard.exe"
     )
   )
 )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Inter-Process Communication
    * ID: T1559
    * Reference URL: [https://attack.mitre.org/techniques/T1559/](https://attack.mitre.org/techniques/T1559/)

* Sub-technique:

    * Name: Component Object Model
    * ID: T1559.001
    * Reference URL: [https://attack.mitre.org/techniques/T1559/001/](https://attack.mitre.org/techniques/T1559/001/)



