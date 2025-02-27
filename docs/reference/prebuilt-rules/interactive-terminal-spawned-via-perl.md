---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/interactive-terminal-spawned-via-perl.html
---

# Interactive Terminal Spawned via Perl [interactive-terminal-spawned-via-perl]

Identifies when a terminal (tty) is spawned via Perl. Attackers may upgrade a simple reverse shell to a fully interactive tty after obtaining initial access to a host.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*
* endgame-*

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
* Resources: Investigation Guide

**Version**: 109

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_439]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Interactive Terminal Spawned via Perl**

Perl, a versatile scripting language, can execute system commands, making it a target for adversaries seeking to escalate privileges or maintain persistence. Attackers may exploit Perl to spawn interactive terminals, transforming basic shells into robust command interfaces. The detection rule identifies such activity by monitoring process events on Linux systems, specifically when Perl executes shell commands, signaling potential misuse.

**Possible investigation steps**

* Review the process event logs to confirm the presence of a Perl process with arguments indicating the execution of a shell, such as "exec \"/bin/sh\";", "exec \"/bin/dash\";", or "exec \"/bin/bash\";".
* Identify the user account associated with the Perl process to determine if it aligns with expected activity or if it suggests unauthorized access.
* Examine the parent process of the Perl execution to understand how the Perl script was initiated and assess if it correlates with legitimate user activity or a potential compromise.
* Check for any network connections or data transfers initiated by the Perl process to identify possible exfiltration or communication with external command and control servers.
* Investigate any recent changes to user accounts, permissions, or scheduled tasks that might indicate privilege escalation or persistence mechanisms associated with the Perl activity.
* Correlate the event with other security alerts or logs from the same host to identify patterns or additional indicators of compromise that could suggest a broader attack campaign.

**False positive analysis**

* System maintenance scripts that use Perl to execute shell commands may trigger this rule. Review and whitelist known maintenance scripts by adding exceptions for specific script paths or process arguments.
* Automated deployment tools that utilize Perl for executing shell commands can cause false positives. Identify these tools and exclude their specific process arguments or execution paths from the detection rule.
* Development environments where Perl is used for testing or debugging purposes might inadvertently spawn interactive terminals. Consider excluding processes initiated by known development user accounts or within specific development directories.
* Backup or monitoring scripts that rely on Perl to perform system checks or data collection could be flagged. Analyze these scripts and create exceptions based on their unique process arguments or execution context.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious Perl processes identified by the detection rule to halt any ongoing malicious activity.
* Conduct a thorough review of the affected system’s logs and process history to identify any additional indicators of compromise or related malicious activity.
* Reset credentials and review access permissions for any accounts that may have been compromised or used in the attack.
* Restore the affected system from a known good backup to ensure any malicious changes are removed.
* Implement additional monitoring on the affected host and network to detect any further attempts to exploit Perl for spawning interactive terminals.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if broader organizational impacts exist.


## Setup [_setup_276]

**Setup**

This rule requires data coming in from one of the following integrations: - Elastic Defend - Auditbeat

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

**Auditbeat Setup**

Auditbeat is a lightweight shipper that you can install on your servers to audit the activities of users and processes on your systems. For example, you can use Auditbeat to collect and centralize audit events from the Linux Audit Framework. You can also use Auditbeat to detect changes to critical files, like binaries and configuration files, and identify potential security policy violations.

**The following steps should be executed in order to add the Auditbeat on a Linux System:**

* Elastic provides repositories available for APT and YUM-based distributions. Note that we provide binary packages, but no source packages.
* To install the APT and YUM repositories follow the setup instructions in this [helper guide](beats://docs/reference/auditbeat/setup-repositories.md).
* To run Auditbeat on Docker follow the setup instructions in the [helper guide](beats://docs/reference/auditbeat/running-on-docker.md).
* To run Auditbeat on Kubernetes follow the setup instructions in the [helper guide](beats://docs/reference/auditbeat/running-on-kubernetes.md).
* For complete “Setup and Run Auditbeat” information refer to the [helper guide](beats://docs/reference/auditbeat/setting-up-running.md).


## Rule query [_rule_query_474]

```js
event.category:process and host.os.type:linux and event.type:(start or process_started) and process.name:perl and
  process.args:("exec \"/bin/sh\";" or "exec \"/bin/dash\";" or "exec \"/bin/bash\";")
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



