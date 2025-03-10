---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-interactive-terminal-spawned-via-python.html
---

# Interactive Terminal Spawned via Python [prebuilt-rule-8-17-4-interactive-terminal-spawned-via-python]

Identifies when a terminal (tty) is spawned via Python. Attackers may upgrade a simple reverse shell to a fully interactive tty after obtaining initial access to a host.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4405]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Interactive Terminal Spawned via Python**

Python’s ability to spawn interactive terminals is a powerful feature often used for legitimate administrative tasks. However, adversaries can exploit this to escalate a basic reverse shell into a fully interactive terminal, enhancing their control over a compromised system. The detection rule identifies such abuse by monitoring processes where Python spawns a shell, focusing on specific patterns in process arguments and parent-child process relationships, indicating potential malicious activity.

**Possible investigation steps**

* Review the process tree to understand the parent-child relationship, focusing on the parent process named "python*" and the child process that is a shell (e.g., bash, sh, zsh).
* Examine the command-line arguments of the parent Python process to identify the use of "pty.spawn" and the presence of the "-c" flag, which may indicate an attempt to spawn an interactive terminal.
* Check the process start event details, including the timestamp and user context, to determine if the activity aligns with expected administrative tasks or if it appears suspicious.
* Investigate the source IP address and user account associated with the process to assess if they are known and authorized entities within the network.
* Look for any related alerts or logs that might indicate prior suspicious activity, such as initial access vectors or other execution attempts, to build a timeline of events.
* Correlate this activity with any recent changes or incidents reported on the host to determine if this is part of a larger attack or an isolated event.

**False positive analysis**

* Administrative scripts or automation tools that use Python to manage system processes may trigger this rule. To handle this, identify and whitelist specific scripts or tools that are known to perform legitimate tasks.
* Developers or system administrators using Python for interactive debugging or system management might inadvertently match the rule’s criteria. Consider excluding processes initiated by trusted user accounts or within specific directories associated with development or administration.
* Scheduled tasks or cron jobs that utilize Python to execute shell commands could be mistaken for malicious activity. Review and exclude these tasks by specifying their unique process arguments or parent-child process relationships.
* Security tools or monitoring solutions that leverage Python for executing shell commands as part of their normal operation may also trigger this rule. Identify these tools and create exceptions based on their process signatures or execution context.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious Python processes identified in the alert, especially those spawning shell processes, to disrupt the attacker’s control.
* Conduct a thorough review of the affected system for any additional signs of compromise, such as unauthorized user accounts, scheduled tasks, or modified system files.
* Reset credentials for any accounts accessed from the compromised host to prevent further unauthorized access.
* Apply security patches and updates to the affected system to address any vulnerabilities that may have been exploited.
* Enhance monitoring and logging on the affected host and network to detect any similar activities in the future, focusing on process creation and network connections.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.


## Setup [_setup_1249]

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


## Rule query [_rule_query_5397]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start") and
(
  (process.parent.name : "python*" and process.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh",
   "fish") and process.parent.args_count >= 3 and process.parent.args : "*pty.spawn*" and process.parent.args : "-c") or
  (process.parent.name : "python*" and process.name in ("bash", "dash", "ash", "sh", "tcsh", "csh", "zsh", "ksh",
   "fish") and process.args : "*sh" and process.args_count == 1 and process.parent.args_count == 1)
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

    * Name: Python
    * ID: T1059.006
    * Reference URL: [https://attack.mitre.org/techniques/T1059/006/](https://attack.mitre.org/techniques/T1059/006/)



