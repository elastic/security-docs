---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/container-management-utility-run-inside-a-container.html
---

# Container Management Utility Run Inside A Container [container-management-utility-run-inside-a-container]

This rule detects when a container management binary is run from inside a container. These binaries are critical components of many containerized environments, and their presence and execution in unauthorized containers could indicate compromise or a misconfiguration.

**Rule type**: eql

**Rule indices**:

* logs-cloud_defend*

**Severity**: low

**Risk score**: 21

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

**Rule license**: Elastic Licence v2

## Investigation guide [_investigation_guide_234]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Container Management Utility Run Inside A Container**

Container management utilities like Docker and Kubernetes are essential for orchestrating and managing containerized applications. They facilitate tasks such as deployment, scaling, and networking. However, adversaries can exploit these tools to execute unauthorized commands within containers, potentially leading to system compromise. The detection rule identifies suspicious execution of these utilities within containers, signaling possible misuse or misconfiguration, by monitoring specific process activities and event types.

**Possible investigation steps**

* Review the specific container ID where the suspicious process was executed to determine its purpose and origin.
* Examine the process name and command line arguments to understand the context of the execution and identify any anomalies or unauthorized commands.
* Check the user and permissions associated with the process to assess if it aligns with expected roles and access levels for container management tasks.
* Investigate the container’s creation and deployment history to identify any recent changes or deployments that could explain the presence of the management utility.
* Analyze network activity associated with the container to detect any unusual connections or data transfers that might indicate malicious activity.
* Correlate the event with other security alerts or logs to identify patterns or related incidents that could provide additional context or evidence of compromise.

**False positive analysis**

* Routine maintenance tasks within containers can trigger the rule. Exclude known maintenance scripts or processes by adding them to an allowlist if they frequently execute container management utilities.
* Development and testing environments often run container management commands for legitimate purposes. Consider excluding these environments from monitoring or adjust the rule to focus on production environments only.
* Automated deployment tools may execute container management commands as part of their workflow. Identify these tools and create exceptions for their activities to prevent false positives.
* System updates or patches might involve running container management utilities. Monitor update schedules and temporarily adjust the rule to avoid unnecessary alerts during these periods.
* Legitimate administrative actions by authorized personnel can trigger the rule. Implement user-based exceptions for known administrators to reduce false positives while maintaining security oversight.

**Response and remediation**

* Immediately isolate the affected container to prevent further unauthorized access or execution of commands. This can be done by stopping the container or disconnecting it from the network.
* Review the container’s configuration and access controls to identify any misconfigurations or unauthorized access permissions that may have allowed the execution of container management utilities.
* Conduct a thorough analysis of the container’s logs and process activities to determine the extent of the compromise and identify any additional malicious activities or lateral movement attempts.
* Remove any unauthorized or suspicious binaries and scripts from the container to prevent further exploitation.
* Patch and update the container image and underlying host system to address any known vulnerabilities that may have been exploited.
* Implement stricter access controls and monitoring on container management utilities to ensure they are only accessible by authorized users and processes.
* Escalate the incident to the security operations team for further investigation and to assess the need for broader security measures across the container environment.


## Rule query [_rule_query_243]

```js
process where container.id: "*" and event.type== "start"
  and process.name: ("dockerd", "docker", "kubelet", "kube-proxy", "kubectl", "containerd", "runc", "systemd", "crictl")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Container Administration Command
    * ID: T1609
    * Reference URL: [https://attack.mitre.org/techniques/T1609/](https://attack.mitre.org/techniques/T1609/)



