---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-container-escape-via-modified-notify-on-release-file.html
---

# Potential Container Escape via Modified notify_on_release File [prebuilt-rule-8-17-4-potential-container-escape-via-modified-notify-on-release-file]

This rule detects modification of the cgroup notify_on_release file from inside a container. When the notify_on_release flag is enabled (1) in a cgroup, then whenever the last task in the cgroup exits or attaches to another cgroup, the command specified in the release_agent file is run and invoked from the host. A privileged container with SYS_ADMIN capabilities, enables a threat actor to mount a cgroup directory and modify the notify_on_release flag in order to take advantage of this feature, which could be used for further privilege escalation and container escapes to the host machine.

**Rule type**: eql

**Rule indices**:

* logs-cloud_defend*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

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

## Investigation guide [_investigation_guide_4133]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Container Escape via Modified notify_on_release File**

In containerized environments, the `notify_on_release` file in cgroups can trigger host-level commands when a cgroup becomes empty. Adversaries exploit this by modifying the file from privileged containers, potentially executing unauthorized commands on the host. The detection rule monitors changes to `notify_on_release` files, flagging suspicious modifications indicative of privilege escalation attempts.

**Possible investigation steps**

* Review the alert details to confirm the file involved is indeed the "notify_on_release" file and verify the event.module is "cloud_defend" with event.action as "open" and event.type as "change".
* Identify the container from which the modification attempt originated by examining the associated metadata, such as container ID or name, to understand the context of the alert.
* Check the privileges and capabilities assigned to the container, specifically looking for SYS_ADMIN capabilities, which could allow modification of cgroup settings.
* Investigate the release_agent file associated with the cgroup to determine if any unauthorized or suspicious commands are configured to execute upon cgroup release.
* Review recent activity logs and command history within the container to identify any anomalous behavior or commands that could indicate an attempt to exploit the notify_on_release mechanism.
* Assess the potential impact on the host system by determining if any unauthorized commands have been executed as a result of the modification, and evaluate the need for containment or remediation actions.

**False positive analysis**

* Routine maintenance tasks in containerized environments may involve legitimate modifications to the notify_on_release file. Users should verify if such changes align with scheduled maintenance activities.
* Automated container orchestration tools might modify cgroup settings, including the notify_on_release file, as part of their normal operations. Users can create exceptions for known orchestration tools by identifying their specific process IDs or user accounts.
* Some containerized applications may require modifications to cgroup settings for performance tuning or resource management. Users should document these applications and exclude their expected behavior from triggering alerts.
* Development and testing environments often involve frequent changes to container configurations, including cgroup files. Users can reduce noise by applying the rule only to production environments or by setting up separate monitoring profiles for non-production systems.
* If a specific container consistently triggers alerts without malicious intent, users can whitelist the container by its unique identifier or image name, ensuring that only unexpected changes are flagged.

**Response and remediation**

* Immediately isolate the affected container to prevent further unauthorized actions. This can be done by stopping the container or disconnecting it from the network.
* Review and revoke any unnecessary privileges or capabilities, such as SYS_ADMIN, from the container to minimize the risk of exploitation.
* Inspect the release_agent file associated with the cgroup to identify any unauthorized commands or scripts that may have been set for execution.
* Remove or reset any malicious or unauthorized entries in the release_agent file to prevent further execution of host-level commands.
* Conduct a thorough audit of the host system for any signs of compromise or unauthorized access, focusing on logs and system changes around the time of the alert.
* Patch and update the container runtime and host operating system to address any known vulnerabilities that could facilitate container escapes.
* Enhance monitoring and alerting for similar activities by ensuring that all cgroup modifications are logged and reviewed regularly, and consider implementing additional security controls such as AppArmor or SELinux to restrict container capabilities.


## Rule query [_rule_query_5150]

```js
file where event.module == "cloud_defend" and event.action == "open" and
event.type == "change" and file.name : "notify_on_release"
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



