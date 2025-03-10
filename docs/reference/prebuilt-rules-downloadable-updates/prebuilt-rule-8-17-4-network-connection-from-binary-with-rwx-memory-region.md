---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-network-connection-from-binary-with-rwx-memory-region.html
---

# Network Connection from Binary with RWX Memory Region [prebuilt-rule-8-17-4-network-connection-from-binary-with-rwx-memory-region]

Monitors for the execution of a unix binary with read, write and execute memory region permissions, followed by a network connection. The mprotect() system call is used to change the access protections on a region of memory that has already been allocated. This syscall allows a process to modify the permissions of pages in its virtual address space, enabling or disabling permissions such as read, write, and execute for those pages. RWX permissions on memory is in many cases overly permissive, and should (especially in conjunction with an outbound network connection) be analyzed thoroughly.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
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
* Data Source: Elastic Defend
* Data Source: Auditd Manager
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4398]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Network Connection from Binary with RWX Memory Region**

In Linux environments, the `mprotect()` system call adjusts memory permissions, potentially enabling read, write, and execute (RWX) access. Adversaries exploit this to execute malicious code in memory, often followed by network connections to exfiltrate data or communicate with command-and-control servers. The detection rule identifies such behavior by monitoring for RWX memory changes and subsequent network activity, flagging suspicious processes for further analysis.

**Possible investigation steps**

* Review the process details using the process.pid and process.name fields to identify the binary that requested RWX memory permissions.
* Investigate the context of the mprotect() syscall by examining the process’s command line arguments and parent process to understand its origin and purpose.
* Analyze the network connection details, focusing on the destination.ip field, to determine if the connection was made to a known malicious IP or an unusual external server.
* Check the process’s execution history and any associated files or scripts to identify potential malicious payloads or scripts that may have been executed.
* Correlate the event with other security logs or alerts from the same host.id to identify any related suspicious activities or patterns.
* Assess the risk and impact by determining if any sensitive data was accessed or exfiltrated during the network connection attempt.

**False positive analysis**

* Legitimate software updates or patches may temporarily use RWX memory regions. Monitor the specific process names and verify if they are associated with known update mechanisms. Consider adding these processes to an exception list if they are verified as safe.
* Development tools and environments often require RWX permissions for debugging or testing purposes. Identify these tools and exclude them from the rule if they are part of a controlled and secure development environment.
* Certain system services or daemons, like custom web servers or network services, might use RWX memory regions for legitimate reasons. Review the process names and network destinations to determine if they are part of expected system behavior, and exclude them if confirmed.
* Security software or monitoring tools may exhibit this behavior as part of their normal operation. Validate these processes and consider excluding them if they are recognized as part of your security infrastructure.
* Custom scripts or automation tasks that require dynamic code execution might trigger this rule. Ensure these scripts are reviewed and approved, then exclude them if they are deemed non-threatening.

**Response and remediation**

* Isolate the affected host from the network immediately to prevent further data exfiltration or communication with potential command-and-control servers.
* Terminate the suspicious process identified by the detection rule to halt any ongoing malicious activity.
* Conduct a memory dump of the affected system to capture the current state for forensic analysis, focusing on the RWX memory regions.
* Review and analyze the network logs to identify any external IP addresses or domains the process attempted to connect to, and block these on the network firewall.
* Patch and update the affected system to the latest security updates to mitigate any known vulnerabilities that could have been exploited.
* Implement stricter memory protection policies to prevent processes from obtaining RWX permissions unless absolutely necessary.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if this is part of a larger attack campaign.


## Setup [_setup_1242]

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


## Rule query [_rule_query_5390]

```js
sample by host.id, process.pid, process.name
  /* auditd.data.a2 == "7" translates to RWX memory region protection (PROT_READ | PROT_WRITE | PROT_EXEC) */
  [process where host.os.type == "linux" and auditd.data.syscall == "mprotect" and auditd.data.a2 == "7" and
   not process.name == "httpd"]
  [network where host.os.type == "linux" and event.type == "start" and event.action == "connection_attempted" and
   not cidrmatch(destination.ip, "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1")]
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

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Application Layer Protocol
    * ID: T1071
    * Reference URL: [https://attack.mitre.org/techniques/T1071/](https://attack.mitre.org/techniques/T1071/)



