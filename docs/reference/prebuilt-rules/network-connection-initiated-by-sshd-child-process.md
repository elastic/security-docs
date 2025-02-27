---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/network-connection-initiated-by-sshd-child-process.html
---

# Network Connection Initiated by SSHD Child Process [network-connection-initiated-by-sshd-child-process]

This rule identifies an egress internet connection initiated by an SSH Daemon child process. This behavior is indicative of the alteration of a shell configuration file or other mechanism that launches a process when a new SSH login occurs. Attackers can also backdoor the SSH daemon to allow for persistence, call out to a C2 or to steal credentials.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://hadess.io/the-art-of-linux-persistence/](https://hadess.io/the-art-of-linux-persistence/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_574]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Network Connection Initiated by SSHD Child Process**

The SSH Daemon (SSHD) facilitates secure remote logins and command execution on Linux systems. Adversaries may exploit SSHD by modifying shell configurations or backdooring the daemon to establish unauthorized connections, often for persistence or data exfiltration. The detection rule identifies suspicious outbound connections initiated by SSHD child processes, excluding benign processes and internal IP ranges, to flag potential malicious activity.

**Possible investigation steps**

* Review the process details of the SSHD child process that initiated the network connection, focusing on the process.entity_id and process.parent.entity_id to understand the process hierarchy and parent-child relationship.
* Examine the destination IP address of the network connection attempt to determine if it is associated with known malicious activity or suspicious external entities, especially since it is not within the excluded internal IP ranges.
* Investigate the executable path of the process that initiated the connection to ensure it is not a known benign process like "/bin/yum" or "/usr/bin/yum", and verify if the process name is not among the excluded ones such as "login_duo", "ssh", "sshd", or "sshd-session".
* Check the timing and frequency of the SSHD child process executions and network connection attempts to identify any patterns or anomalies that could indicate unauthorized or persistent access attempts.
* Correlate the alert with other security events or logs from the same host.id to gather additional context and determine if there are other indicators of compromise or related suspicious activities.

**False positive analysis**

* Internal administrative scripts or tools that initiate network connections upon SSH login can trigger false positives. To manage this, identify and whitelist these specific scripts or tools by their process names or executable paths.
* Automated software updates or package management processes like yum may occasionally initiate network connections. Exclude these processes by adding them to the exception list using their executable paths.
* Security tools such as login_duo or other authentication mechanisms that establish network connections during SSH sessions can be mistaken for malicious activity. Exclude these tools by specifying their process names in the exception list.
* Custom monitoring or logging solutions that connect to external servers for data aggregation might be flagged. Identify these processes and exclude them by their executable paths or process names to prevent false alerts.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified as child processes of SSHD that are attempting unauthorized network connections.
* Conduct a thorough review of SSHD configuration files and shell configuration files for unauthorized modifications or backdoors, and restore them from a known good backup if necessary.
* Change all credentials associated with the affected system, especially those that may have been exposed or used during the unauthorized SSH sessions.
* Apply security patches and updates to the SSH daemon and related software to mitigate known vulnerabilities that could be exploited for persistence or unauthorized access.
* Monitor network traffic for any further suspicious outbound connections from other systems, indicating potential lateral movement or additional compromised hosts.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the scope of the compromise.


## Rule query [_rule_query_615]

```js
sequence by host.id with maxspan=1s
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.parent.executable == "/usr/sbin/sshd"] by process.entity_id
  [network where host.os.type == "linux" and event.type == "start" and event.action == "connection_attempted" and not (
     destination.ip == null or destination.ip == "0.0.0.0" or cidrmatch(
     destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
     "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
     "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
     "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
     "FF00::/8", "172.31.0.0/16"
     )
    ) and not (
      process.executable in ("/bin/yum", "/usr/bin/yum") or
      process.name in ("login_duo", "ssh", "sshd", "sshd-session")
    )
  ] by process.parent.entity_id
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Unix Shell Configuration Modification
    * ID: T1546.004
    * Reference URL: [https://attack.mitre.org/techniques/T1546/004/](https://attack.mitre.org/techniques/T1546/004/)

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

* Technique:

    * Name: Remote Service Session Hijacking
    * ID: T1563
    * Reference URL: [https://attack.mitre.org/techniques/T1563/](https://attack.mitre.org/techniques/T1563/)

* Sub-technique:

    * Name: SSH Hijacking
    * ID: T1563.001
    * Reference URL: [https://attack.mitre.org/techniques/T1563/001/](https://attack.mitre.org/techniques/T1563/001/)

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)



