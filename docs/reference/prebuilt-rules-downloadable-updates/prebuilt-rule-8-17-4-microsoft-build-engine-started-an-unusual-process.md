---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-microsoft-build-engine-started-an-unusual-process.html
---

# Microsoft Build Engine Started an Unusual Process [prebuilt-rule-8-17-4-microsoft-build-engine-started-an-unusual-process]

An instance of MSBuild, the Microsoft Build Engine, started a PowerShell script or the Visual C# Command Line Compiler. This technique is sometimes used to deploy a malicious payload using the Build Engine.

**Rule type**: new_terms

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.*
* logs-system.security*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.talosintelligence.com/2020/02/building-bypass-with-msbuild.html](https://blog.talosintelligence.com/2020/02/building-bypass-with-msbuild.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Execution
* Data Source: Elastic Defend
* Data Source: System
* Resources: Investigation Guide

**Version**: 315

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4763]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft Build Engine Started an Unusual Process**

The Microsoft Build Engine (MSBuild) is a platform for building applications, often used in software development environments. Adversaries may exploit MSBuild to execute malicious scripts or compile code, bypassing security controls. The detection rule identifies unusual processes initiated by MSBuild, such as PowerShell or C# compiler, signaling potential misuse for executing unauthorized or harmful actions.

**Possible investigation steps**

* Review the process tree to understand the parent-child relationship, focusing on MSBuild.exe or msbuild.exe as the parent process and any unusual child processes like csc.exe, iexplore.exe, or powershell.exe.
* Examine the command line arguments used by the unusual process to identify any suspicious or malicious scripts or commands being executed.
* Check the user account associated with the process to determine if it aligns with expected usage patterns or if it might be compromised.
* Investigate the source and integrity of the MSBuild project file (.proj or .sln) to ensure it hasn’t been tampered with or used to execute unauthorized code.
* Analyze recent changes or deployments in the environment that might explain the unusual process execution, such as new software installations or updates.
* Correlate this event with other security alerts or logs to identify any patterns or additional indicators of compromise that might suggest a broader attack.

**False positive analysis**

* Development environments often use MSBuild to execute legitimate PowerShell scripts or compile C# code. Regularly review and whitelist known development processes to prevent unnecessary alerts.
* Automated build systems may trigger this rule when running scripts or compiling code as part of their normal operation. Identify and exclude these systems by their hostnames or IP addresses.
* Some software installations or updates might use MSBuild to execute scripts. Monitor and document these activities, and create exceptions for recognized software vendors.
* Internal tools or scripts that rely on MSBuild for execution should be cataloged. Establish a baseline of expected behavior and exclude these from triggering alerts.
* Collaborate with development teams to understand their use of MSBuild and adjust the detection rule to accommodate their workflows without compromising security.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further execution of potentially malicious processes and lateral movement.
* Terminate any suspicious processes initiated by MSBuild, such as PowerShell or the C# compiler, to halt any ongoing malicious activity.
* Conduct a thorough review of the affected system for any unauthorized changes or additional malicious files, focusing on scripts or executables that may have been deployed.
* Restore the system from a known good backup if any malicious activity or unauthorized changes are confirmed, ensuring that the backup is clean and uncompromised.
* Escalate the incident to the security operations team for further analysis and to determine if the threat is part of a larger attack campaign.
* Implement additional monitoring and logging for MSBuild and related processes to detect any future misuse or anomalies promptly.
* Review and update endpoint protection configurations to enhance detection and prevention capabilities against similar threats, ensuring that security controls are effectively blocking unauthorized script execution.


## Setup [_setup_1531]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_5718]

```js
host.os.type:windows and event.category:process and event.type:start and process.parent.name:("MSBuild.exe" or "msbuild.exe") and
process.name:("csc.exe" or "iexplore.exe" or "powershell.exe")
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

* Sub-technique:

    * Name: Compile After Delivery
    * ID: T1027.004
    * Reference URL: [https://attack.mitre.org/techniques/T1027/004/](https://attack.mitre.org/techniques/T1027/004/)

* Technique:

    * Name: Trusted Developer Utilities Proxy Execution
    * ID: T1127
    * Reference URL: [https://attack.mitre.org/techniques/T1127/](https://attack.mitre.org/techniques/T1127/)

* Sub-technique:

    * Name: MSBuild
    * ID: T1127.001
    * Reference URL: [https://attack.mitre.org/techniques/T1127/001/](https://attack.mitre.org/techniques/T1127/001/)



