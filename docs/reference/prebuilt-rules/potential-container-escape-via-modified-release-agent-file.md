---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-container-escape-via-modified-release-agent-file.html
---

# Potential Container Escape via Modified release_agent File [potential-container-escape-via-modified-release-agent-file]

This rule detects modification of the CGroup release_agent file from inside a privileged container. The release_agent is a script that is executed at the termination of any process on that CGroup and is invoked from the host. A privileged container with SYS_ADMIN capabilities, enables a threat actor to mount a CGroup directory and modify the release_agent which could be used for further privilege escalation and container escapes to the host machine.

**Rule type**: eql

**Rule indices**:

* logs-cloud_defend*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.aquasec.com/threat-alert-container-escape](https://blog.aquasec.com/threat-alert-container-escape)
* [https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)
* [https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation#privileged-escape-abusing-existent-release_agent-cve-2022-0492-poc1](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation#privileged-escape-abusing-existent-release_agent-cve-2022-0492-poc1)

**Tags**:

* Data Source: Elastic Defend for Containers
* Domain: Container
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_655]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Container Escape via Modified release_agent File**

In containerized environments, the release_agent file in CGroup directories can execute scripts upon process termination. Adversaries exploit this by modifying the file from privileged containers, potentially escalating privileges or escaping to the host. The detection rule monitors changes to the release_agent file, flagging unauthorized modifications indicative of such exploits.

**Possible investigation steps**

* Review the alert details to confirm the file involved is the release_agent file and that the event.module is "cloud_defend" with event.action as "open" and event.type as "change".
* Identify the container from which the modification attempt originated, focusing on whether it has SYS_ADMIN capabilities, which could indicate a privileged container.
* Check the history of the release_agent file for any recent changes or modifications, including timestamps and user accounts involved, to understand the context of the modification.
* Investigate the processes running within the container at the time of the alert to identify any suspicious or unauthorized activities that could be related to privilege escalation attempts.
* Examine the network activity and connections from the container to detect any unusual outbound traffic that might suggest an attempt to communicate with external systems or exfiltrate data.
* Review system logs and audit logs on the host for any signs of unauthorized access or privilege escalation attempts that coincide with the alert timestamp.
* Assess the security posture of the container environment, including the configuration of CGroup directories and permissions, to identify potential vulnerabilities that could be exploited for container escape.

**False positive analysis**

* Routine maintenance scripts or system updates may modify the release_agent file without malicious intent. Users can create exceptions for known maintenance activities by identifying the specific processes or scripts involved and excluding them from the rule.
* Automated container management tools might access and modify the release_agent file as part of their normal operations. Users should verify the legitimacy of these tools and whitelist their actions to prevent unnecessary alerts.
* Custom container orchestration solutions could interact with the release_agent file for legitimate reasons. Users should document these interactions and configure the rule to ignore changes made by these trusted solutions.
* Development and testing environments often involve frequent changes to container configurations, including the release_agent file. Users can reduce false positives by setting up separate monitoring profiles for these environments, allowing more lenient detection thresholds.

**Response and remediation**

* Immediately isolate the affected container to prevent further unauthorized actions or potential spread to other containers or the host system.
* Revoke SYS_ADMIN capabilities from the container to limit its ability to modify critical system files and directories.
* Conduct a thorough review of the modified release_agent file to identify any malicious scripts or commands that may have been inserted.
* Restore the release_agent file to its original state from a known good backup to ensure no unauthorized scripts are executed.
* Investigate the source of the privilege escalation to determine how the adversary gained SYS_ADMIN capabilities and address any security gaps.
* Escalate the incident to the security operations team for further analysis and to assess the potential impact on the host system.
* Implement additional monitoring and alerting for changes to critical files and directories within privileged containers to enhance detection of similar threats in the future.


## Rule query [_rule_query_697]

```js
file where event.module == "cloud_defend" and event.action == "open" and
event.type == "change" and file.name : "release_agent"
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



