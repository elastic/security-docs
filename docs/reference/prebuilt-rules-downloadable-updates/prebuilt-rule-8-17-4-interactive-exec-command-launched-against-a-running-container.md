---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-interactive-exec-command-launched-against-a-running-container.html
---

# Interactive Exec Command Launched Against A Running Container [prebuilt-rule-8-17-4-interactive-exec-command-launched-against-a-running-container]

This rule detects interactive *exec* events launched against a container using the *exec* command. Using the *exec* command in a pod allows a user to establish a temporary shell session and execute any process/command inside the container. This rule specifically targets higher-risk interactive commands that allow real-time interaction with a container’s shell. A malicious actor could use this level of access to further compromise the container environment or attempt a container breakout.

**Rule type**: eql

**Rule indices**:

* logs-cloud_defend*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
* [https://kubernetes.io/docs/tasks/debug/debug-application/get-shell-running-container/](https://kubernetes.io/docs/tasks/debug/debug-application/get-shell-running-container/)

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

## Investigation guide [_investigation_guide_4125]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Interactive Exec Command Launched Against A Running Container**

In containerized environments, the *exec* command is used to run processes inside a running container, often for debugging or administrative tasks. Adversaries may exploit this to gain shell access, potentially leading to further compromise or container escape. The detection rule identifies such activities by monitoring for interactive *exec* sessions, focusing on initial processes within containers, and flagging high-risk interactions.

**Possible investigation steps**

* Review the container.id to identify which specific container the interactive exec command was executed against and gather information about its purpose and criticality.
* Examine the process.entry_leader.entry_meta.type to confirm that the process was indeed initiated within a container environment, ensuring the context of the alert is accurate.
* Investigate the process.entry_leader.same_as_process field to verify that the process in question is the initial process run in the container, which may indicate a new or unexpected session.
* Analyze the process.interactive field to understand the nature of the interaction and determine if it aligns with expected administrative activities or if it suggests unauthorized access.
* Check for any recent changes or deployments in the container environment that might explain the interactive session, such as updates or debugging activities.
* Correlate the event with user activity logs to identify the user or service account responsible for initiating the exec command and assess their access permissions and recent actions.
* Investigate any subsequent actions or commands executed within the container following the interactive session to identify potential malicious activities or attempts at container breakout.

**False positive analysis**

* Routine administrative tasks may trigger the rule when system administrators use *kubectl exec* for legitimate maintenance or debugging. To manage this, create exceptions for known administrator accounts or specific maintenance windows.
* Automated scripts or monitoring tools that use *exec* for health checks or logging purposes can also cause false positives. Identify these scripts and exclude their associated processes or user accounts from triggering the rule.
* Development and testing activities often involve frequent use of *exec* commands for container interaction. Consider excluding specific development environments or user roles from the rule to reduce noise.
* Continuous integration/continuous deployment (CI/CD) pipelines might use *exec* to deploy or test applications within containers. Exclude these pipeline processes or service accounts to prevent false alerts.
* If certain containers are known to require frequent interactive access for legitimate reasons, consider tagging these containers and configuring the rule to ignore interactions with them.

**Response and remediation**

* Immediately isolate the affected container to prevent further unauthorized access or potential lateral movement within the environment. This can be done by pausing or stopping the container.
* Review and terminate any unauthorized or suspicious interactive sessions identified by the alert to cut off the adversary’s access.
* Conduct a thorough analysis of the container’s filesystem and running processes to identify any malicious scripts or binaries that may have been introduced during the interactive session.
* Revert the container to a known good state by redeploying it from a trusted image, ensuring that any potential backdoors or malicious modifications are removed.
* Implement network segmentation and access controls to limit the ability of users to execute *exec* commands on containers, especially for high-risk or production environments.
* Escalate the incident to the security operations team for further investigation and to determine if additional containers or systems have been compromised.
* Enhance monitoring and alerting for similar activities by ensuring that all interactive *exec* commands are logged and reviewed, and consider implementing stricter access controls for container management tools like kubectl.


## Rule query [_rule_query_5142]

```js
process where container.id : "*" and event.type== "start" and

/* use of kubectl exec to enter a container */
process.entry_leader.entry_meta.type : "container" and

/* process is the inital process run in a container */
process.entry_leader.same_as_process== true and

/* interactive process */
process.interactive == true
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

* Technique:

    * Name: Container Administration Command
    * ID: T1609
    * Reference URL: [https://attack.mitre.org/techniques/T1609/](https://attack.mitre.org/techniques/T1609/)



