---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-reverse-shell-via-child.html
---

# Potential Reverse Shell via Child [potential-reverse-shell-via-child]

This detection rule identifies suspicious network traffic patterns associated with TCP reverse shell activity. This activity consists of a network event that is followed by the creation of a shell process with suspicious command line arguments. An attacker may establish a Linux TCP reverse shell to gain remote access to a target system.

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

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_763]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Reverse Shell via Child**

Reverse shells are a technique where attackers gain remote access to a system by initiating a connection from the target back to the attacker’s machine. This is often achieved using shell processes like bash or socat. Adversaries exploit this by executing commands remotely, bypassing firewalls. The detection rule identifies such activity by monitoring for network events followed by suspicious shell process executions, focusing on unusual command-line arguments and parent-child process relationships.

**Possible investigation steps**

* Review the network event details to identify the source and destination IP addresses involved in the connection attempt or acceptance. Pay special attention to any external IP addresses that are not part of the internal network.
* Examine the process execution details, focusing on the command-line arguments used by the shell process. Look for unusual or suspicious arguments such as "-i" or "-l" that may indicate interactive or login shells.
* Investigate the parent-child process relationship, especially if the parent process is "socat" with arguments containing "exec". This could suggest an attempt to execute a reverse shell.
* Check the timeline of events to determine if the network event and shell process execution occurred within a short time frame (maxspan=5s), which may indicate a coordinated attack.
* Correlate the alert with any other recent suspicious activities on the host, such as unauthorized access attempts or changes in system configurations, to assess the broader context of the potential threat.
* Verify the legitimacy of the involved processes and connections by consulting with system owners or reviewing system documentation to rule out any false positives due to legitimate administrative activities.

**False positive analysis**

* Legitimate administrative scripts or tools that use shell processes with interactive flags may trigger the rule. To manage this, identify and document these scripts, then create exceptions for their specific command-line arguments or parent processes.
* Automated maintenance tasks or cron jobs that involve shell execution with similar command-line arguments can be mistaken for reverse shell activity. Review these tasks and exclude them by specifying their unique process names or arguments.
* Development or testing environments where developers frequently use shell processes for debugging or testing purposes might cause false positives. Consider excluding these environments by filtering based on host identifiers or specific user accounts.
* Network monitoring tools or legitimate applications that use socat for network connections may appear suspicious. Identify these applications and exclude their specific process names or parent-child relationships from the detection rule.
* Custom scripts or applications that mimic reverse shell behavior for legitimate purposes should be reviewed and excluded by adding their specific process names or command-line patterns to the exception list.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious shell processes identified by the detection rule, especially those initiated by or involving the listed shell programs (e.g., bash, socat).
* Conduct a forensic analysis of the affected system to identify any additional indicators of compromise, such as unauthorized user accounts or modified system files.
* Review and reset credentials for any accounts that may have been compromised, ensuring the use of strong, unique passwords.
* Apply relevant security patches and updates to the affected system to address any vulnerabilities that may have been exploited.
* Monitor network traffic for any further suspicious activity, particularly outgoing connections to unknown or suspicious IP addresses.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_490]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a Linux System:**

* Go to the Kibana home page and click Add integrations.
* In the query bar, search for Elastic Defend and select the integration to see more details about it.
* Click Add Elastic Defend.
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, either Traditional Endpoints or Cloud Workloads.
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest to select "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in New agent policy name. If other agent policies already exist, you can click the Existing hosts tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click Save and Continue.
* To complete the integration, select Add Elastic Agent to your hosts and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_811]

```js
sequence by host.id, process.entity_id with maxspan=5s
  [network where event.type == "start" and host.os.type == "linux" and
     event.action in ("connection_attempted", "connection_accepted") and
     process.name : ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish", "socat") and destination.ip != null and
     not cidrmatch(destination.ip, "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1")]
  [process where event.type == "start" and host.os.type == "linux" and event.action == "exec" and
     process.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and (
       (process.args : ("-i", "-l")) or (process.parent.name == "socat" and process.parent.args : "*exec*")
   )]
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



