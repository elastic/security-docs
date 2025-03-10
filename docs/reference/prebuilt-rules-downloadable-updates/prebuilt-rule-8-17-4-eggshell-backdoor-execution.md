---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-eggshell-backdoor-execution.html
---

# EggShell Backdoor Execution [prebuilt-rule-8-17-4-eggshell-backdoor-execution]

Identifies the execution of and EggShell Backdoor. EggShell is a known post exploitation tool for macOS and Linux.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/neoneggplant/EggShell](https://github.com/neoneggplant/EggShell)

**Tags**:

* Domain: Endpoint
* OS: Linux
* OS: macOS
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3965]

**Triage and analysis**

[TBC: QUOTE]
**Investigating EggShell Backdoor Execution**

EggShell is a post-exploitation tool used on macOS and Linux systems, allowing adversaries to execute commands and scripts remotely. It leverages command and scripting interpreters to gain control over compromised systems. Attackers exploit this by executing malicious payloads, maintaining persistence, and exfiltrating data. The detection rule identifies suspicious process activities, specifically targeting the execution patterns and arguments associated with EggShell, to alert analysts of potential backdoor usage.

**Possible investigation steps**

* Review the alert details to confirm the presence of the process name *espl* and check if the process arguments start with *eyJkZWJ1ZyI6*, which indicates potential EggShell activity.
* Investigate the parent process of *espl* to understand how it was initiated and identify any associated suspicious activities or processes.
* Examine the user account under which the *espl* process was executed to determine if it aligns with expected behavior or if it indicates a compromised account.
* Check for any network connections or data exfiltration attempts associated with the *espl* process to assess if data has been sent to an external source.
* Review system logs and other security alerts around the time of the *espl* process execution to identify any correlated events or anomalies.
* Assess the persistence mechanisms on the affected system to determine if the EggShell backdoor has established any means to survive reboots or user logouts.

**False positive analysis**

* Legitimate administrative scripts or tools that use similar command patterns to EggShell may trigger false positives. Review the process arguments and context to determine if the activity is expected and authorized.
* Development or testing environments where EggShell or similar tools are used for legitimate purposes can cause alerts. Implement exceptions for these environments by excluding specific user accounts or process paths.
* Automated scripts or monitoring tools that mimic EggShell’s execution patterns might be flagged. Identify these scripts and create exceptions based on their unique identifiers or execution context.
* Regularly update the detection rule to refine the criteria based on observed false positives, ensuring that legitimate activities are not continuously flagged.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further command execution and data exfiltration.
* Terminate any suspicious processes associated with the EggShell backdoor, specifically those matching the process name *espl* and arguments starting with *eyJkZWJ1ZyI6*.
* Conduct a thorough examination of the system to identify any additional malicious payloads or persistence mechanisms that may have been deployed by the attacker.
* Remove any unauthorized user accounts or access credentials that may have been created or compromised during the exploitation.
* Restore the system from a known good backup to ensure all traces of the backdoor and any associated malware are eradicated.
* Update and patch all software and systems to close any vulnerabilities that may have been exploited by the attacker.
* Enhance monitoring and detection capabilities to identify similar threats in the future, focusing on command and scripting interpreter activities as outlined in MITRE ATT&CK technique T1059.


## Rule query [_rule_query_4982]

```js
event.category:process and event.type:(process_started or start) and process.name:espl and process.args:eyJkZWJ1ZyI6*
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

    * Name: Python
    * ID: T1059.006
    * Reference URL: [https://attack.mitre.org/techniques/T1059/006/](https://attack.mitre.org/techniques/T1059/006/)



