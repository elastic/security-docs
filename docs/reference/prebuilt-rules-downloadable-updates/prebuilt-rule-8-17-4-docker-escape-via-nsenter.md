---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-docker-escape-via-nsenter.html
---

# Docker Escape via Nsenter [prebuilt-rule-8-17-4-docker-escape-via-nsenter]

This rule identifies a UID change event via `nsenter`. The `nsenter` command is used to enter a namespace, which is a way to isolate processes and resources. Attackers can use `nsenter` to escape from a container to the host, which can lead to privilege escalation and lateral movement.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.cyberark.com/resources/threat-research-blog/the-route-to-root-container-escape-using-kernel-exploitation](https://www.cyberark.com/resources/threat-research-blog/the-route-to-root-container-escape-using-kernel-exploitation)

**Tags**:

* Domain: Endpoint
* Domain: Container
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4515]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Docker Escape via Nsenter**

Docker containers use namespaces to isolate processes, ensuring they operate independently from the host system. The `nsenter` command allows users to access these namespaces, which is essential for managing containerized environments. However, adversaries can exploit `nsenter` to break out of a container, gaining unauthorized access to the host system. The detection rule identifies suspicious UID changes involving `nsenter`, signaling potential container escapes and privilege escalation attempts.

**Possible investigation steps**

* Review the alert details to confirm the presence of a UID change event involving the nsenter command, as indicated by the query fields.
* Identify the container from which the nsenter command was executed by examining the process.entry_leader.entry_meta.type field.
* Investigate the process arguments to verify the use of nsenter with the -t or --target options, ensuring the process.args_count is 4 or more, which may indicate an attempt to target a specific namespace.
* Check the user and process context before and after the UID change to understand the potential impact and scope of the privilege escalation.
* Analyze the container’s logs and any associated host logs around the time of the event to gather additional context and identify any suspicious activities or patterns.
* Assess the container’s configuration and security settings to determine if there are any vulnerabilities or misconfigurations that could have been exploited.
* If unauthorized access is confirmed, initiate incident response procedures to contain and remediate the threat, including reviewing other containers and systems for similar activities.

**False positive analysis**

* Routine administrative tasks using nsenter can trigger false positives, especially when system administrators use it for legitimate container management. To mitigate this, create exceptions for known administrative scripts or processes that frequently use nsenter.
* Automated monitoring tools or scripts that perform health checks or maintenance on containers might use nsenter, leading to false alerts. Identify these tools and whitelist their specific processes or user accounts to reduce noise.
* Development environments where developers frequently enter containers for debugging purposes can cause false positives. Consider excluding specific development user accounts or container IDs from the rule to prevent unnecessary alerts.
* Continuous integration and deployment pipelines that interact with containers might use nsenter as part of their operations. Review these pipelines and exclude their associated processes or user accounts to avoid false detections.

**Response and remediation**

* Immediately isolate the affected container to prevent further unauthorized access to the host system. This can be done by stopping the container or disconnecting it from the network.
* Conduct a thorough review of the container’s logs and processes to identify any unauthorized changes or suspicious activities that occurred before and after the UID change event.
* Revoke any unauthorized access or credentials that may have been compromised during the container escape attempt. Ensure that all access keys and passwords are rotated.
* Patch and update the container image and host system to address any vulnerabilities that may have been exploited. Ensure that the latest security updates are applied.
* Implement stricter namespace and capability restrictions for containers to minimize the risk of privilege escalation. Consider using security tools like AppArmor or SELinux to enforce these restrictions.
* Monitor for any further suspicious activity on the host system and other containers, focusing on similar UID change events or unauthorized use of `nsenter`.
* Escalate the incident to the security operations team for a comprehensive investigation and to assess the potential impact on the broader network and systems.


## Rule query [_rule_query_5507]

```js
process where host.os.type == "linux" and event.type == "change" and event.action == "uid_change" and
process.entry_leader.entry_meta.type == "container" and process.args == "nsenter" and
process.args in ("-t", "--target") and process.args_count >= 4
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Escape to Host
    * ID: T1611
    * Reference URL: [https://attack.mitre.org/techniques/T1611/](https://attack.mitre.org/techniques/T1611/)



