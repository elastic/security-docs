---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-ssh-connection-established-inside-a-running-container.html
---

# SSH Connection Established Inside A Running Container [prebuilt-rule-8-17-4-ssh-connection-established-inside-a-running-container]

This rule detects an incoming SSH connection established inside a running container. Running an ssh daemon inside a container should be avoided and monitored closely if necessary. If an attacker gains valid credentials they can use it to gain initial access or establish persistence within a compromised environment.

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

**Tags**:

* Data Source: Elastic Defend for Containers
* Domain: Container
* OS: Linux
* Use Case: Threat Detection
* Tactic: Initial Access
* Tactic: Lateral Movement
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4128]

**Triage and analysis**

[TBC: QUOTE]
**Investigating SSH Connection Established Inside A Running Container**

SSH (Secure Shell) is a protocol used to securely access and manage systems remotely. In containerized environments, running an SSH daemon is generally discouraged due to security risks. Adversaries may exploit SSH to gain unauthorized access or maintain persistence within a compromised container. The detection rule identifies SSH connections initiated within containers by monitoring for SSH daemon processes that start new sessions, indicating potential unauthorized access attempts. This rule is crucial for identifying and mitigating threats related to initial access and lateral movement within containerized environments.

**Possible investigation steps**

* Review the container ID associated with the alert to identify the specific container where the SSH connection was established.
* Examine the process details, particularly focusing on the entry leader and session leader fields, to determine if the SSH daemon process is the initial process or part of a new session within the container.
* Check for any interactive sessions initiated by the SSH daemon to confirm if the connection was actively used for interaction.
* Investigate the source of the SSH connection by analyzing network logs or connection details to identify the originating IP address and assess if it is known or suspicious.
* Correlate the event with user activity logs to determine if the SSH connection aligns with expected user behavior or if it indicates potential unauthorized access.
* Assess the container’s configuration and security posture to understand why an SSH daemon is running and evaluate if it is necessary or a security oversight.
* Review any recent changes or deployments related to the container to identify potential vulnerabilities or misconfigurations that could have been exploited.

**False positive analysis**

* Legitimate administrative access to containers via SSH may trigger the rule. To manage this, create exceptions for known administrative IP addresses or user accounts that regularly access containers for maintenance.
* Automated scripts or tools that use SSH for legitimate purposes, such as configuration management or deployment, can cause false positives. Identify these tools and exclude their specific process signatures or user accounts from the rule.
* Development or testing environments where SSH is used for debugging or monitoring may also trigger alerts. Consider excluding these environments by tagging them appropriately and adjusting the rule to ignore these tags.
* Containers running legacy applications that require SSH for functionality might be flagged. Document these applications and create exceptions based on their specific container IDs or hostnames.

**Response and remediation**

* Immediately isolate the affected container to prevent further unauthorized access or lateral movement within the environment.
* Terminate the SSH daemon process running inside the container to cut off any active unauthorized sessions.
* Conduct a thorough review of access logs and container activity to identify any unauthorized access attempts or suspicious behavior.
* Revoke any compromised credentials and enforce a password reset for affected accounts to prevent further unauthorized access.
* Deploy updated container images without SSH daemons and ensure that future container deployments adhere to security best practices.
* Implement network segmentation to limit access to containerized environments and reduce the attack surface for similar threats.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on the broader environment.


## Rule query [_rule_query_5145]

```js
process where container.id: "*" and event.type == "start" and

/* use of sshd to enter a container*/
process.entry_leader.entry_meta.type: "sshd"  and

/* process is the initial process run in a container or start of a new session*/
(process.entry_leader.same_as_process== true or process.session_leader.same_as_process== true) and

/* interactive process*/
process.interactive== true
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: External Remote Services
    * ID: T1133
    * Reference URL: [https://attack.mitre.org/techniques/T1133/](https://attack.mitre.org/techniques/T1133/)

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



