---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-meterpreter-reverse-shell.html
---

# Potential Meterpreter Reverse Shell [prebuilt-rule-8-17-4-potential-meterpreter-reverse-shell]

This detection rule identifies a sample of suspicious Linux system file reads used for system fingerprinting, leveraged by the Metasploit Meterpreter shell to gather information about the target that it is executing its shell on. Detecting this pattern is indicative of a successful meterpreter shell connection.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-auditd_manager.auditd-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/primer-on-persistence-mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)
* [https://www.elastic.co/security-labs/linux-detection-engineering-with-auditd](https://www.elastic.co/security-labs/linux-detection-engineering-with-auditd)

**Tags**:

* Data Source: Auditd Manager
* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Resources: Investigation Guide

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4414]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Meterpreter Reverse Shell**

Meterpreter is a sophisticated payload within the Metasploit framework, enabling attackers to execute commands and scripts on compromised systems. Adversaries exploit it to perform system reconnaissance and data exfiltration. The detection rule identifies suspicious file access patterns typical of Meterpreter’s system fingerprinting activities, such as reading key system files, indicating a potential reverse shell connection.

**Possible investigation steps**

* Review the process associated with the alert by examining the process ID (process.pid) and user ID (user.id) to determine if the process is legitimate or potentially malicious.
* Check the host ID (host.id) to identify the specific system where the suspicious activity was detected and assess if it is a high-value target or has been previously compromised.
* Investigate the command history and running processes on the affected host to identify any unusual or unauthorized activities that may indicate a Meterpreter session.
* Analyze network connections from the host to detect any suspicious outbound connections that could suggest a reverse shell communication.
* Examine the file access patterns, particularly the access to files like /etc/machine-id, /etc/passwd, /proc/net/route, /proc/net/ipv6_route, and /proc/net/if_inet6, to understand the context and purpose of these reads and whether they align with normal system operations.
* Correlate the alert with other security events or logs from the same timeframe to identify any additional indicators of compromise or related malicious activities.

**False positive analysis**

* System administration scripts or tools that perform regular checks on system files like /etc/machine-id or /etc/passwd may trigger this rule. To manage this, identify and whitelist these legitimate processes by their process ID or user ID.
* Backup or monitoring software that accesses network configuration files such as /proc/net/route or /proc/net/ipv6_route can cause false positives. Exclude these applications by adding exceptions for their specific file access patterns.
* Security tools that perform network diagnostics or inventory checks might read files like /proc/net/if_inet6. Review these tools and exclude their known benign activities from triggering the rule.
* Custom scripts used for system health checks or inventory management that access the flagged files should be reviewed. If deemed safe, add them to an exception list based on their host ID or user ID.

**Response and remediation**

* Isolate the affected system from the network immediately to prevent further data exfiltration or lateral movement by the attacker.
* Terminate any suspicious processes identified by the detection rule, particularly those associated with the process IDs flagged in the alert.
* Conduct a thorough review of the affected system’s logs and file access history to identify any additional unauthorized access or data exfiltration attempts.
* Change all credentials and keys that may have been exposed or compromised on the affected system, especially those related to user accounts identified in the alert.
* Restore the affected system from a known good backup to ensure any malicious changes are removed, and verify the integrity of the restored system.
* Implement network segmentation to limit the potential impact of future attacks and enhance monitoring of critical systems for similar suspicious activities.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_1258]

**Setup**

This rule requires data coming in from one of the following integrations: - Auditbeat - Auditd Manager

**Auditbeat Setup**

Auditbeat is a lightweight shipper that you can install on your servers to audit the activities of users and processes on your systems. For example, you can use Auditbeat to collect and centralize audit events from the Linux Audit Framework. You can also use Auditbeat to detect changes to critical files, like binaries and configuration files, and identify potential security policy violations.

**The following steps should be executed in order to add the Auditbeat on a Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://reference/auditbeat/setup-repositories.md).
* To run Auditbeat on Docker follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-docker.md).
* To run Auditbeat on Kubernetes follow the setup instructions in the [helper guide](beats://reference/auditbeat/running-on-kubernetes.md).
* For complete “Setup and Run Auditbeat” information refer to the [helper guide](beats://reference/auditbeat/setting-up-running.md).

**Auditd Manager Integration Setup**

The Auditd Manager Integration receives audit events from the Linux Audit Framework which is a part of the Linux kernel. Auditd Manager provides a user-friendly interface and automation capabilities for configuring and monitoring system auditing through the auditd daemon. With `auditd_manager`, administrators can easily define audit rules, track system events, and generate comprehensive audit reports, improving overall security and compliance in the system.

**The following steps should be executed in order to add the Elastic Agent System integration "auditd_manager" on a Linux System:**

* Go to the Kibana home page and click “Add integrations”.
* In the query bar, search for “Auditd Manager” and select the integration to see more details about it.
* Click “Add Auditd Manager”.
* Configure the integration name and optionally add a description.
* Review optional and advanced settings accordingly.
* Add the newly installed “auditd manager” to an existing or a new agent policy, and deploy the agent on a Linux system from which auditd log files are desirable.
* Click “Save and Continue”.
* For more details on the integration refer to the [helper guide](https://docs.elastic.co/integrations/auditd_manager).

**Rule Specific Setup Note**

Auditd Manager subscribes to the kernel and receives events as they occur without any additional configuration. However, if more advanced configuration is required to detect specific behavior, audit rules can be added to the integration in either the "audit rules" configuration box or the "auditd rule files" box by specifying a file to read the audit rules from. - For this detection rule the following additional audit rules are required to be added to the integration: -w /proc/net/ -p r -k audit_proc -w /etc/machine-id -p wa -k machineid -w /etc/passwd -p wa -k passwd


## Rule query [_rule_query_5406]

```js
sample by host.id, process.pid, user.id
  [file where host.os.type == "linux" and auditd.data.syscall == "open" and auditd.data.a2 == "1b6" and file.path == "/etc/machine-id"]
  [file where host.os.type == "linux" and auditd.data.syscall == "open" and auditd.data.a2 == "1b6" and file.path == "/etc/passwd"]
  [file where host.os.type == "linux" and auditd.data.syscall == "open" and auditd.data.a2 == "1b6" and file.path == "/proc/net/route"]
  [file where host.os.type == "linux" and auditd.data.syscall == "open" and auditd.data.a2 == "1b6" and file.path == "/proc/net/ipv6_route"]
  [file where host.os.type == "linux" and auditd.data.syscall == "open" and auditd.data.a2 == "1b6" and file.path == "/proc/net/if_inet6"]
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



