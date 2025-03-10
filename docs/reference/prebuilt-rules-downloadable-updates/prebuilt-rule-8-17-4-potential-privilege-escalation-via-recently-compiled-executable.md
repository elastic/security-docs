---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-privilege-escalation-via-recently-compiled-executable.html
---

# Potential Privilege Escalation via Recently Compiled Executable [prebuilt-rule-8-17-4-potential-privilege-escalation-via-recently-compiled-executable]

This rule monitors a sequence involving a program compilation event followed by its execution and a subsequent alteration of UID permissions to root privileges. This behavior can potentially indicate the execution of a kernel or software privilege escalation exploit.

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
* Tactic: Privilege Escalation
* Use Case: Vulnerability
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4541]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Privilege Escalation via Recently Compiled Executable**

In Linux environments, compiling and executing programs is a routine operation. However, adversaries can exploit this by compiling malicious code to escalate privileges. This detection rule identifies suspicious sequences where a non-root user compiles and executes a program, followed by a UID change to root, indicating potential privilege escalation attempts. By monitoring these patterns, the rule helps in identifying and mitigating exploitation risks.

**Possible investigation steps**

* Review the alert details to identify the specific non-root user involved in the compilation and execution sequence. Check the user.id field to gather more information about the user’s activities and permissions.
* Examine the process.args field from the initial compilation event to understand the source code or script being compiled. This can provide insights into whether the code has malicious intent.
* Investigate the file.name field associated with the creation event to determine the nature of the executable file created. Check its location and any associated metadata for anomalies.
* Analyze the process.name field from the execution event to identify the program that was run. Cross-reference this with known malicious binaries or scripts.
* Check the process.name field in the UID change event to identify the process responsible for the privilege escalation. Determine if this process is known to exploit vulnerabilities for privilege escalation.
* Review system logs and other security tools for any additional suspicious activities or anomalies around the time of the alert to gather more context on the potential threat.
* Assess the system for any signs of compromise or unauthorized changes, such as new user accounts, altered configurations, or unexpected network connections, to evaluate the impact and scope of the incident.

**False positive analysis**

* Development activities by legitimate users can trigger this rule when compiling and testing new software. To manage this, consider creating exceptions for specific users or groups known to perform regular development tasks.
* Automated build systems or continuous integration pipelines may compile and execute code as part of their normal operation. Exclude these systems by identifying their user accounts or host identifiers.
* System administrators performing maintenance or updates might compile and execute programs, leading to false positives. Implement exceptions for these users or specific maintenance windows.
* Educational environments where students frequently compile and execute code for learning purposes can generate alerts. Exclude these activities by setting up exceptions for student user accounts or specific lab environments.
* Security testing and research activities that involve compiling and executing exploit code in a controlled manner can be mistaken for malicious behavior. Exclude these activities by identifying the user accounts or systems involved in such testing.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious processes identified in the alert, especially those associated with the compiled executable and any processes running with elevated privileges.
* Revert any unauthorized changes to user permissions, particularly any UID changes to root, to restore the system to its secure state.
* Conduct a thorough review of the affected system for additional indicators of compromise, such as unauthorized file modifications or new user accounts, and remove any malicious artifacts.
* Apply relevant security patches and updates to the system to address any vulnerabilities that may have been exploited for privilege escalation.
* Monitor the affected system and network for any signs of recurring or related suspicious activity, using enhanced logging and alerting mechanisms.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be affected, ensuring comprehensive remediation across the environment.


## Setup [_setup_1373]

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


## Rule query [_rule_query_5533]

```js
sequence by host.id with maxspan=1m
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name in ("gcc", "g++", "cc") and user.id != "0"] by process.args
  [file where host.os.type == "linux" and event.action == "creation" and event.type == "creation" and
   process.name == "ld" and user.id != "0"] by file.name
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   user.id != "0"] by process.name
  [process where host.os.type == "linux" and event.action in ("uid_change", "guid_change") and event.type == "change" and
   user.id == "0"] by process.name
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)



