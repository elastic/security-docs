---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unknown-execution-of-binary-with-rwx-memory-region.html
---

# Unknown Execution of Binary with RWX Memory Region [prebuilt-rule-8-17-4-unknown-execution-of-binary-with-rwx-memory-region]

Monitors for the execution of a previously unknown unix binary with read, write and execute memory region permissions. The mprotect() system call is used to change the access protections on a region of memory that has already been allocated. This syscall allows a process to modify the permissions of pages in its virtual address space, enabling or disabling permissions such as read, write, and execute for those pages. RWX permissions on memory is in many cases overly permissive, and should be analyzed thoroughly.

**Rule type**: new_terms

**Rule indices**:

* auditbeat-*
* logs-auditd_manager.auditd-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://man7.org/linux/man-pages/man2/mprotect.2.html](https://man7.org/linux/man-pages/man2/mprotect.2.md)
* [https://www.elastic.co/security-labs/linux-detection-engineering-with-auditd](https://www.elastic.co/security-labs/linux-detection-engineering-with-auditd)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Auditd Manager
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4424]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unknown Execution of Binary with RWX Memory Region**

In Linux environments, the `mprotect()` system call is crucial for managing memory permissions, allowing processes to modify access rights of memory pages. Adversaries exploit this by granting read, write, and execute (RWX) permissions to inject and execute malicious code. The detection rule identifies suspicious RWX memory allocations by monitoring `mprotect()` calls, excluding known safe binaries, thus highlighting potential threats.

**Possible investigation steps**

* Review the process details associated with the alert, focusing on the process.executable and process.name fields to identify the binary that triggered the alert.
* Investigate the command line arguments and parent process of the suspicious binary to understand its origin and purpose.
* Check the process’s hash against known threat intelligence databases to determine if it is associated with any known malicious activity.
* Analyze the network activity of the process to identify any suspicious connections or data exfiltration attempts.
* Examine the user account under which the process is running to assess if it has been compromised or is being used for unauthorized activities.
* Review recent system logs and audit records for any other anomalies or related suspicious activities around the time of the alert.

**False positive analysis**

* Known safe binaries like Node.js, Java, and Apache may trigger the rule due to their legitimate use of RWX memory regions. These are already excluded in the rule, but additional similar applications might need to be added to the exclusion list.
* Custom or in-house developed applications that require RWX permissions for legitimate functionality can also cause false positives. Identify these applications and add them to the exclusion list to prevent unnecessary alerts.
* Development environments or testing frameworks that dynamically generate and execute code might be flagged. Consider excluding these environments if they are known and trusted within your organization.
* Security tools or monitoring software that perform memory analysis or manipulation could be mistakenly identified. Verify their behavior and exclude them if they are part of your security infrastructure.
* Regularly review and update the exclusion list to ensure it reflects the current environment and any new applications that are introduced.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement or data exfiltration by the malicious code.
* Terminate the suspicious process identified by the detection rule to halt any ongoing malicious activity.
* Conduct a forensic analysis of the affected system to identify the source and scope of the compromise, focusing on the unknown binary and its origin.
* Remove any malicious binaries or scripts identified during the forensic analysis to prevent further execution.
* Apply security patches and updates to the affected system to address any vulnerabilities that may have been exploited.
* Restore the system from a known good backup if the integrity of the system is in question and ensure all security patches are applied post-restoration.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_1267]

**Setup**

This rule requires the use of the `auditd_manager` integration. `Auditd_manager` is a tool designed to simplify and enhance the management of the audit subsystem in Linux systems. It provides a user-friendly interface and automation capabilities for configuring and monitoring system auditing through the auditd daemon. With `auditd_manager`, administrators can easily define audit rules, track system events, and generate comprehensive audit reports, improving overall security and compliance in the system. The following steps should be executed in order to install and deploy `auditd_manager` on a Linux system.

```
Kibana -->
Management -->
Integrations -->
Auditd Manager -->
Add Auditd Manager
```

`Auditd_manager` subscribes to the kernel and receives events as they occur without any additional configuration. However, if more advanced configuration is required to detect specific behavior, audit rules can be added to the integration in either the "audit rules" configuration box or the "auditd rule files" box by specifying a file to read the audit rules from. For this detection rule to trigger, the following additional audit rules are required to be added to the integration:

```
-a always,exit -F arch=b64 -S mprotect
```

Add the newly installed `auditd manager` to an agent policy, and deploy the agent on a Linux system from which auditd log files are desirable.


## Rule query [_rule_query_5416]

```js
event.category:process and host.os.type:linux and auditd.data.syscall:mprotect and auditd.data.a2:7 and not (
  process.executable:(
    "/usr/share/kibana/node/bin/node" or "/usr/share/elasticsearch/jdk/bin/java" or "/usr/sbin/apache2"
  ) or
  process.name:(httpd or java)
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



