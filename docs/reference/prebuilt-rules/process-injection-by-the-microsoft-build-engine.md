---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/process-injection-by-the-microsoft-build-engine.html
---

# Process Injection by the Microsoft Build Engine [process-injection-by-the-microsoft-build-engine]

An instance of MSBuild, the Microsoft Build Engine, created a thread in another process. This technique is sometimes used to evade detection or elevate privileges.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.sysmon_operational-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Privilege Escalation
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_837]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Process Injection by the Microsoft Build Engine**

The Microsoft Build Engine (MSBuild) is a platform for building applications, often used in software development environments. Adversaries exploit MSBuild to perform process injection, a technique to execute malicious code within the address space of another process, thereby evading detection and potentially escalating privileges. The detection rule identifies suspicious MSBuild activity by monitoring for thread creation in other processes, leveraging Sysmon data to flag potential abuse.

**Possible investigation steps**

* Review the alert details to confirm that the process name is "MSBuild.exe" and the event action is "CreateRemoteThread detected (rule: CreateRemoteThread)".
* Examine the parent process of MSBuild.exe to determine if it was launched by a legitimate application or user, which could indicate whether the activity is expected or suspicious.
* Check the timeline of events to see if there are any other related alerts or activities around the same time, such as unusual network connections or file modifications, which could provide additional context.
* Investigate the target process where the thread was created to assess its normal behavior and determine if it is a common target for injection or if it has been compromised.
* Analyze the command line arguments used to launch MSBuild.exe to identify any unusual or suspicious parameters that could indicate malicious intent.
* Review the user account associated with the MSBuild.exe process to verify if it has the necessary permissions and if the activity aligns with the user’s typical behavior.
* Consult threat intelligence sources to check if there are any known campaigns or malware that utilize MSBuild for process injection, which could help in understanding the potential threat actor or objective.

**False positive analysis**

* Development environments often use MSBuild for legitimate purposes, which can trigger false positives. Users should monitor and establish a baseline of normal MSBuild activity to differentiate between benign and suspicious behavior.
* Automated build systems may frequently invoke MSBuild, leading to false positives. Consider excluding known build server IP addresses or specific user accounts associated with these systems from the detection rule.
* Some legitimate software may use MSBuild for plugin or extension loading, which could appear as process injection. Identify and whitelist these applications by their process hashes or paths to reduce noise.
* Regular updates or installations of software development tools might cause MSBuild to create threads in other processes. Temporarily disable the rule during scheduled maintenance windows to prevent unnecessary alerts.
* Collaborate with development teams to understand their use of MSBuild and adjust the detection rule to exclude known safe operations, ensuring that only unexpected or unauthorized uses are flagged.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate the MSBuild.exe process if it is confirmed to be involved in unauthorized thread creation, using task management tools or scripts.
* Conduct a memory analysis on the affected system to identify and extract any injected code or payloads for further investigation.
* Review and restore any altered or compromised system files and configurations to their original state using known good backups.
* Escalate the incident to the security operations center (SOC) or incident response team for a comprehensive investigation and to determine the scope of the intrusion.
* Implement application whitelisting to prevent unauthorized execution of MSBuild.exe or similar tools in non-development environments.
* Enhance monitoring and detection capabilities by ensuring Sysmon is configured to log detailed process creation and thread injection events across the network.


## Rule query [_rule_query_893]

```js
process where host.os.type == "windows" and process.name: "MSBuild.exe" and
    event.action:("CreateRemoteThread detected (rule: CreateRemoteThread)", "CreateRemoteThread")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)

* Technique:

    * Name: Trusted Developer Utilities Proxy Execution
    * ID: T1127
    * Reference URL: [https://attack.mitre.org/techniques/T1127/](https://attack.mitre.org/techniques/T1127/)

* Sub-technique:

    * Name: MSBuild
    * ID: T1127.001
    * Reference URL: [https://attack.mitre.org/techniques/T1127/001/](https://attack.mitre.org/techniques/T1127/001/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)



