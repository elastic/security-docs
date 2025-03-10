---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-interactive-shell-spawned-from-inside-a-container.html
---

# Suspicious Interactive Shell Spawned From Inside A Container [prebuilt-rule-8-17-4-suspicious-interactive-shell-spawned-from-inside-a-container]

This rule detects when an interactive shell is spawned inside a running container. This could indicate a potential container breakout attempt or an attacker’s attempt to gain unauthorized access to the underlying host.

**Rule type**: eql

**Rule indices**:

* logs-cloud_defend*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Data Source: Elastic Defend for Containers
* Domain: Container
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4126]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Interactive Shell Spawned From Inside A Container**

Containers are lightweight, portable units that encapsulate applications and their dependencies, often used to ensure consistent environments across development and production. Adversaries may exploit containers by spawning interactive shells to execute unauthorized commands, potentially leading to container escape and host compromise. The detection rule identifies such threats by monitoring for shell processes initiated within containers, focusing on specific process actions and arguments indicative of interactive sessions.

**Possible investigation steps**

* Review the alert details to identify the specific container ID where the interactive shell was spawned. This will help in isolating the affected container for further analysis.
* Examine the process executable and arguments, particularly looking for shell types and interactive flags (e.g., "-i", "-it"), to understand the nature of the shell session initiated.
* Check the process entry leader to determine if the shell process is part of a larger process tree, which might indicate a more complex attack chain or script execution.
* Investigate the user context under which the shell was spawned to assess if it aligns with expected user behavior or if it indicates potential unauthorized access.
* Analyze recent logs and events from the container and host to identify any preceding suspicious activities or anomalies that might have led to the shell spawning.
* Correlate the event with other security alerts or incidents to determine if this is part of a broader attack pattern or campaign targeting the environment.

**False positive analysis**

* Development and testing activities may trigger this rule when developers intentionally spawn interactive shells within containers for debugging or configuration purposes. To manage this, create exceptions for specific user accounts or container IDs frequently used in development environments.
* Automated scripts or orchestration tools that use interactive shells for legitimate tasks can also cause false positives. Identify these scripts and exclude their associated process names or arguments from the rule.
* Some container management platforms might use interactive shells as part of their normal operations. Review the processes and arguments used by these platforms and add them to an exception list if they are known to be safe.
* Regular maintenance tasks that require interactive shell access, such as system updates or configuration changes, can be excluded by scheduling these tasks during known maintenance windows and temporarily adjusting the rule settings.

**Response and remediation**

* Immediately isolate the affected container to prevent further unauthorized access or potential container escape. This can be done by stopping the container or disconnecting it from the network.
* Capture and preserve forensic data from the container, including logs, process lists, and network activity, to aid in further investigation and understanding of the attack vector.
* Conduct a thorough review of the container’s configuration and permissions to identify and rectify any misconfigurations or vulnerabilities that may have been exploited.
* Patch and update the container image and any associated software to address known vulnerabilities that could have been leveraged by the attacker.
* Implement stricter access controls and monitoring on container environments to prevent unauthorized shell access, such as using role-based access controls and enabling audit logging.
* Escalate the incident to the security operations team for further analysis and to determine if the threat has spread to other parts of the infrastructure.
* Review and enhance detection capabilities to identify similar threats in the future, ensuring that alerts are tuned to detect unauthorized shell access attempts promptly.


## Rule query [_rule_query_5143]

```js
process where container.id: "*" and
event.type== "start" and

/*D4C consolidates closely spawned event.actions, this excludes end actions to only capture ongoing processes*/
event.action in ("fork", "exec") and event.action != "end"
 and process.entry_leader.same_as_process== false and
(
(process.executable: "*/*sh" and process.args: ("-i", "-it")) or
process.args: "*/*sh"
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

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)



