---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-network-connection-via-recently-compiled-executable.html
---

# Network Connection via Recently Compiled Executable [prebuilt-rule-8-17-4-network-connection-via-recently-compiled-executable]

This rule monitors a sequence involving a program compilation event followed by its execution and a subsequent network connection event. This behavior can indicate the set up of a reverse tcp connection to a command-and-control server. Attackers may spawn reverse shells to establish persistence onto a target system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4399]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Network Connection via Recently Compiled Executable**

In Linux environments, compiling and executing programs is routine for development. However, adversaries exploit this by compiling malicious code to establish reverse shells, enabling remote control. The detection rule identifies this threat by monitoring sequences of compilation, execution, and network activity, flagging unusual connections that deviate from typical patterns, thus indicating potential compromise.

**Possible investigation steps**

* Review the process execution details to identify the compiler used (e.g., gcc, g++, cc) and examine the arguments passed during the compilation to understand the nature of the compiled code.
* Investigate the file creation event associated with the linker (ld) to determine the output executable file and its location on the system.
* Analyze the subsequent process execution to identify the newly compiled executable and verify its legitimacy by checking its hash against known malware databases.
* Examine the network connection attempt details, focusing on the destination IP address, to determine if it is associated with known malicious activity or command-and-control servers.
* Check the process name involved in the network connection attempt to ensure it is not a commonly used legitimate process, as specified in the query exclusions (e.g., simpleX, conftest, ssh, python, ispnull, pvtui).
* Correlate the timing of the compilation, execution, and network connection events to assess if they align with typical user behavior or indicate suspicious activity.

**False positive analysis**

* Development activities involving frequent compilation and execution of new code can trigger false positives. To manage this, exclude specific user accounts or directories commonly used for legitimate development work.
* Automated build systems or continuous integration pipelines may compile and execute code regularly. Identify and exclude these processes or IP addresses from monitoring to prevent false alerts.
* Legitimate software updates or installations that involve compiling source code can be mistaken for malicious activity. Exclude known update processes or package managers from the rule.
* Network connections to internal or trusted IP addresses that are not part of the typical exclusion list might be flagged. Update the exclusion list to include these trusted IP ranges.
* Certain legitimate applications that compile and execute code as part of their normal operation, such as IDEs or scripting environments, should be identified and excluded from the rule to reduce noise.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified in the alert, especially those related to the recently compiled executable and any associated network connections.
* Conduct a forensic analysis of the affected system to identify any additional indicators of compromise, such as unauthorized user accounts or scheduled tasks.
* Remove any malicious executables or scripts identified during the investigation from the system to prevent re-execution.
* Reset credentials for any accounts that may have been compromised, focusing on those with elevated privileges.
* Update and patch the affected system to close any vulnerabilities that may have been exploited by the attacker.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_1243]

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


## Rule query [_rule_query_5391]

```js
sequence by host.id with maxspan=1m
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name in ("gcc", "g++", "cc")] by process.args
  [file where host.os.type == "linux" and event.action == "creation" and process.name == "ld"] by file.name
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec"] by process.name
  [network where host.os.type == "linux" and event.action == "connection_attempted" and destination.ip != null and not (
     cidrmatch(destination.ip, "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "::1") or
     process.name in ("simpleX", "conftest", "ssh", "python", "ispnull", "pvtui", "npreal2d", "ruby", "source", "ssh")
   )] by process.name
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



