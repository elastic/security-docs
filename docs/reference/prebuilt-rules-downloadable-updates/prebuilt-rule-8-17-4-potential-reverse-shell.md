---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-reverse-shell.html
---

# Potential Reverse Shell [prebuilt-rule-8-17-4-potential-reverse-shell]

This detection rule identifies suspicious network traffic patterns associated with TCP reverse shell activity. This activity consists of a parent-child relationship where a network event is followed by the creation of a shell process. An attacker may establish a Linux TCP reverse shell to gain remote access to a target system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 10

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4416]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Reverse Shell**

Reverse shells are tools that adversaries use to gain remote access to a system by initiating a connection from the target back to the attacker. This detection rule identifies such activity by monitoring for network events followed by shell process creation on Linux systems. It flags suspicious patterns, such as shell processes with interactive flags or spawned by tools like socat, indicating potential unauthorized access attempts.

**Possible investigation steps**

* Review the network event details to identify the source and destination IP addresses involved in the connection attempt or acceptance. Pay special attention to any external IP addresses that are not part of the internal network ranges.
* Examine the process tree to understand the parent-child relationship, focusing on the shell process creation following the network event. Verify if the shell process was spawned by a known tool like socat.
* Check the process arguments for interactive flags such as "-i" or "-l" to determine if the shell was intended to be interactive, which could indicate malicious intent.
* Investigate the user account associated with the process to determine if it is a legitimate user or if there are signs of compromise, such as unusual login times or locations.
* Correlate the event with other security logs or alerts to identify any additional suspicious activities or patterns that might indicate a broader attack campaign.
* Assess the risk and impact of the potential reverse shell by determining if any sensitive data or critical systems could have been accessed or compromised.

**False positive analysis**

* Legitimate administrative tasks using interactive shells may trigger this rule. System administrators often use shells with interactive flags for maintenance. To mitigate, create exceptions for known administrator accounts or specific IP addresses.
* Automated scripts or cron jobs that use shell commands with interactive flags can be mistaken for reverse shells. Review and whitelist these scripts by process name or parent process ID to prevent false alerts.
* Tools like socat are used in legitimate network troubleshooting and testing. If socat is frequently used in your environment, consider excluding specific command patterns or user accounts associated with its legitimate use.
* Development environments may spawn shell processes as part of testing or deployment workflows. Identify and exclude these environments by host ID or process name to reduce noise.
* Internal network connections that match the rule’s criteria but are part of normal operations can be excluded by specifying internal IP ranges or known service accounts.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious shell processes identified by the detection rule, especially those initiated by socat or with interactive flags.
* Conduct a forensic analysis of the affected system to identify any additional indicators of compromise, such as unauthorized user accounts or modified files.
* Review and secure network configurations to ensure that only authorized IP addresses can initiate connections to critical systems.
* Update and patch the affected system and any related software to close vulnerabilities that may have been exploited.
* Implement enhanced monitoring and logging on the affected host and network to detect any further attempts at reverse shell activity.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if broader organizational impacts exist.


## Setup [_setup_1260]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a Linux System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, either "Traditional Endpoints" or "Cloud Workloads".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_5408]

```js
sequence by host.id with maxspan=5s
  [network where event.type == "start" and host.os.type == "linux" and
     event.action in ("connection_attempted", "connection_accepted") and
     process.name : ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "socat") and destination.ip != null and
     not cidrmatch(destination.ip, "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1")] by process.entity_id
  [process where event.type == "start" and host.os.type == "linux" and event.action in ("exec", "fork") and
     process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and (
       (process.args : ("-i", "-l")) or (process.parent.name == "socat" and process.parent.args : "*exec*")
   )] by process.parent.entity_id
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



