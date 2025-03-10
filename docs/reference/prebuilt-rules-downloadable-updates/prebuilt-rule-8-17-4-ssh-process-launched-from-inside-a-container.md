---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-ssh-process-launched-from-inside-a-container.html
---

# SSH Process Launched From Inside A Container [prebuilt-rule-8-17-4-ssh-process-launched-from-inside-a-container]

This rule detects an SSH or SSHD process executed from inside a container. This includes both the client ssh binary and server ssh daemon process. SSH usage inside a container should be avoided and monitored closely when necessary. With valid credentials an attacker may move laterally to other containers or to the underlying host through container breakout. They may also use valid SSH credentials as a persistence mechanism.

**Rule type**: eql

**Rule indices**:

* logs-cloud_defend*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/SSH%20server%20running%20inside%20container/](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/SSH%20server%20running%20inside%20container/)
* [https://www.blackhillsinfosec.com/sshazam-hide-your-c2-inside-of-ssh/](https://www.blackhillsinfosec.com/sshazam-hide-your-c2-inside-of-ssh/)

**Tags**:

* Data Source: Elastic Defend for Containers
* Domain: Container
* OS: Linux
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4129]

**Triage and analysis**

[TBC: QUOTE]
**Investigating SSH Process Launched From Inside A Container**

SSH (Secure Shell) is a protocol used for secure remote access and management of systems. Within container environments, SSH usage is atypical and can signal potential security risks. Adversaries may exploit SSH to move laterally between containers or escape to the host system. The detection rule identifies SSH processes initiated within containers, flagging potential unauthorized access or persistence attempts by monitoring process events and container identifiers.

**Possible investigation steps**

* Review the container identifier (container.id) associated with the SSH process to determine which container initiated the process and assess its intended function.
* Examine the process start event details, including the process name (sshd, ssh, autossh) and event actions (fork, exec), to understand the context and nature of the SSH activity.
* Check for any recent changes or deployments related to the container to identify if the SSH process aligns with expected behavior or recent updates.
* Investigate the source and destination of the SSH connection to determine if it involves unauthorized or suspicious endpoints, potentially indicating lateral movement or an attempt to access the host system.
* Analyze user accounts and credentials used in the SSH session to verify if they are legitimate and authorized for container access, looking for signs of compromised credentials.
* Correlate the SSH activity with other security events or alerts to identify patterns or additional indicators of compromise within the container environment.

**False positive analysis**

* Development and testing environments may intentionally use SSH for debugging or administrative tasks. Users can create exceptions for specific container IDs or hostnames associated with these environments to reduce noise.
* Automated scripts or orchestration tools might use SSH to manage containers. Identify these tools and exclude their process IDs or user accounts from triggering the rule.
* Some legacy applications might rely on SSH for internal communication. Review these applications and whitelist their specific process names or container images to prevent false alerts.
* Containers running SSH for legitimate remote access purposes, such as maintenance, should be documented. Exclude these containers by their unique identifiers or labels to avoid unnecessary alerts.
* Regularly review and update the exclusion list to ensure it aligns with current operational practices and does not inadvertently allow malicious activity.

**Response and remediation**

* Immediately isolate the affected container to prevent potential lateral movement or further unauthorized access. This can be done by stopping the container or disconnecting it from the network.
* Conduct a thorough review of the container’s logs and environment to identify any unauthorized access or changes. Pay special attention to SSH-related logs and any anomalies in user activity.
* Revoke any SSH keys or credentials that may have been compromised. Ensure that all SSH keys used within the container environment are rotated and that access is restricted to only necessary personnel.
* Assess the container image and configuration for vulnerabilities or misconfigurations that may have allowed the SSH process to be initiated. Patch any identified vulnerabilities and update the container image accordingly.
* Implement network segmentation to limit the ability of containers to communicate with each other and the host system, reducing the risk of lateral movement.
* Enhance monitoring and alerting for SSH activity within container environments to ensure rapid detection of similar threats in the future. This includes setting up alerts for any SSH process initiation within containers.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or containers have been affected.


## Rule query [_rule_query_5146]

```js
process where container.id: "*" and event.type== "start" and
event.action in ("fork", "exec") and event.action != "end" and
process.name: ("sshd", "ssh", "autossh")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: SSH
    * ID: T1021.004
    * Reference URL: [https://attack.mitre.org/techniques/T1021/004/](https://attack.mitre.org/techniques/T1021/004/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: External Remote Services
    * ID: T1133
    * Reference URL: [https://attack.mitre.org/techniques/T1133/](https://attack.mitre.org/techniques/T1133/)



