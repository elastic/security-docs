---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-reverse-shell-via-java.html
---

# Potential Reverse Shell via Java [prebuilt-rule-8-17-4-potential-reverse-shell-via-java]

This detection rule identifies the execution of a Linux shell process from a Java JAR application post an incoming network connection. This behavior may indicate reverse shell activity via a Java application.

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

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4412]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Reverse Shell via Java**

Java applications, often run on Linux systems, can be exploited by adversaries to establish reverse shells, allowing remote control over a compromised system. Attackers may execute shell commands via Java processes post-network connection. The detection rule identifies suspicious Java activity by monitoring for shell executions following network connections, excluding benign processes, to flag potential reverse shell attempts.

**Possible investigation steps**

* Review the network connection details, focusing on the destination IP address to determine if it is external or potentially malicious, as the rule excludes common internal and reserved IP ranges.
* Examine the Java process that initiated the network connection, including its executable path and arguments, to identify any unusual or unauthorized JAR files being executed.
* Investigate the child shell process spawned by the Java application, checking its command-line arguments and execution context to assess if it aligns with known reverse shell patterns.
* Cross-reference the parent Java process and the child shell process with known benign applications or services, such as Jenkins or NetExtender, to rule out false positives.
* Analyze historical data for the host to identify any previous similar activities or patterns that might indicate a persistent threat or repeated exploitation attempts.

**False positive analysis**

* Java-based administrative tools like Jenkins may trigger false positives when executing shell commands. Exclude known benign Java applications such as Jenkins by adding their specific JAR paths to the exception list.
* Automated scripts or maintenance tasks that use Java to execute shell commands can be mistaken for reverse shell activity. Identify and exclude these scripts by specifying their unique process arguments or executable paths.
* Development environments where Java applications frequently execute shell commands for testing purposes can generate false alerts. Consider excluding these environments by filtering based on specific host identifiers or network segments.
* Security tools that utilize Java for network operations and shell executions might be flagged. Verify and exclude these tools by adding their process names or executable paths to the exception list.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious Java processes identified in the alert to stop potential reverse shell activity.
* Conduct a thorough review of the affected system’s logs to identify any additional indicators of compromise or lateral movement attempts.
* Remove any unauthorized or malicious Java JAR files and associated scripts from the system.
* Apply security patches and updates to the Java environment and any other vulnerable software on the affected host.
* Restore the system from a known good backup if any unauthorized changes or persistent threats are detected.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_1256]

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


## Rule query [_rule_query_5404]

```js
sequence by host.id with maxspan=5s
  [network where host.os.type == "linux" and event.action in ("connection_accepted", "connection_attempted") and
   process.executable : ("/usr/bin/java", "/bin/java", "/usr/lib/jvm/*", "/usr/java/*") and
   not (destination.ip == null or destination.ip == "0.0.0.0" or cidrmatch(
     destination.ip, "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29",
     "192.0.0.8/32", "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24",
     "192.31.196.0/24", "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10",
     "192.175.48.0/24","198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10",
     "FF00::/8"
    )
  )] by process.entity_id
  [process where host.os.type == "linux" and event.action == "exec" and
   process.parent.executable : ("/usr/bin/java", "/bin/java", "/usr/lib/jvm/*", "/usr/java/*") and
   process.parent.args : "-jar" and process.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
   and not process.parent.args in (
     "/usr/share/java/jenkins.war", "/etc/remote-iot/services/remoteiot.jar",
     "/usr/lib64/NetExtender.jar", "/usr/lib/jenkins/jenkins.war"
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



