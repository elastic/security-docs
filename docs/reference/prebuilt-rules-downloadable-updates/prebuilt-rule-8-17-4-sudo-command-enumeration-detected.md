---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-sudo-command-enumeration-detected.html
---

# Sudo Command Enumeration Detected [prebuilt-rule-8-17-4-sudo-command-enumeration-detected]

This rule monitors for the usage of the sudo -l command, which is used to list the allowed and forbidden commands for the invoking user. Attackers may execute this command to enumerate commands allowed to be executed with sudo permissions, potentially allowing to escalate privileges to root.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4379]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Sudo Command Enumeration Detected**

The sudo command in Linux environments allows users to execute commands with elevated privileges, typically as the root user. Attackers may exploit this by using the `sudo -l` command to list permissible commands, potentially identifying paths to escalate privileges. The detection rule identifies this behavior by monitoring for the execution of `sudo -l` from common shell environments, flagging potential misuse for privilege escalation.

**Possible investigation steps**

* Review the process execution details to confirm the presence of the `sudo -l` command, ensuring the process name is "sudo" and the arguments include "-l" with an argument count of 2.
* Identify the parent process of the `sudo` command to determine the shell environment used, checking if it matches any of the specified shells like "bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", or "fish".
* Investigate the user account that executed the `sudo -l` command to assess if the activity aligns with their typical behavior or if it appears suspicious.
* Check for any recent changes in user permissions or sudoers configuration that might indicate unauthorized modifications.
* Correlate this event with other logs or alerts to identify any subsequent suspicious activities that might suggest privilege escalation attempts.

**False positive analysis**

* System administrators frequently use the sudo -l command to verify their permissions. To reduce noise, consider excluding specific user accounts or groups known for legitimate use.
* Automated scripts or configuration management tools may execute sudo -l as part of routine checks. Identify these scripts and exclude their execution paths or parent processes from the rule.
* Some software installations or updates might invoke sudo -l to check permissions. Monitor and document these processes, then create exceptions for known benign software.
* Developers or testers might use sudo -l during debugging or testing phases. Coordinate with development teams to identify and exclude these activities when they are part of approved workflows.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement by the attacker.
* Review the sudoers file on the affected system to identify any unauthorized or suspicious entries that may have been added or modified, and revert any changes to their original state.
* Terminate any suspicious processes initiated by the user who executed the `sudo -l` command, especially if they are not part of normal operations.
* Reset the password of the user account involved in the alert to prevent further unauthorized access.
* Conduct a thorough review of system logs to identify any additional suspicious activity or commands executed by the user, and assess the scope of potential compromise.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be affected.
* Implement additional monitoring and alerting for similar `sudo -l` command executions across the environment to enhance detection and response capabilities.


## Setup [_setup_1226]

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


## Rule query [_rule_query_5371]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and process.name == "sudo" and process.args == "-l" and
  process.args_count == 2 and process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish") and
  not process.args == "dpkg"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Owner/User Discovery
    * ID: T1033
    * Reference URL: [https://attack.mitre.org/techniques/T1033/](https://attack.mitre.org/techniques/T1033/)



