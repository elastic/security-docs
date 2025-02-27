---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-process-backgrounded-by-unusual-parent.html
---

# Process Backgrounded by Unusual Parent [prebuilt-rule-8-17-4-process-backgrounded-by-unusual-parent]

This rule identifies processes that are backgrounded by an unusual parent process. This behavior may indicate a process attempting to evade detection by hiding its parent process.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.process*
* endgame-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

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
* Tactic: Execution
* Tactic: Persistence
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3942]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Process Backgrounded by Unusual Parent**

In Linux environments, shell processes like bash or zsh can be backgrounded using the *&* operator, allowing them to run independently of the terminal. Adversaries exploit this by launching scripts with unusual parent processes to evade detection. The detection rule identifies such anomalies by monitoring process start events with specific shell invocations and backgrounding indicators, flagging potential evasion attempts.

**Possible investigation steps**

* Review the process start event details to identify the parent process and assess its legitimacy. Pay attention to the process.name and process.args fields to understand the context of the command executed.
* Examine the command line arguments (process.args) for any suspicious patterns or commands that could indicate malicious activity, especially focusing on the use of the *&* operator which backgrounds the process.
* Check the user account associated with the process to determine if it is a known and trusted user. Investigate any anomalies in user behavior or unexpected user accounts.
* Correlate the event with other logs or alerts from the same host to identify any related suspicious activities or patterns, such as other unusual process executions or network connections.
* Investigate the parent process’s history and behavior to determine if it has been involved in other suspicious activities or if it has been compromised.
* Consult threat intelligence sources or databases to see if the command or behavior matches known attack patterns or indicators of compromise (IOCs).

**False positive analysis**

* Routine administrative scripts may trigger this rule if they are executed with backgrounding by system administrators. To manage this, identify and whitelist known administrative scripts that are frequently used in your environment.
* Automated maintenance tasks or cron jobs that use shell scripts with backgrounding can also be flagged. Review and exclude these tasks by adding exceptions for specific scripts or processes that are verified as non-threatening.
* Development environments where developers frequently test scripts in the background might cause false positives. Consider creating exceptions for specific user accounts or directories where development activities are known to occur.
* Monitoring tools or agents that use shell scripts to perform checks or gather data in the background could be mistakenly identified. Verify these tools and exclude their processes from the rule to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential lateral movement by the adversary.
* Terminate the suspicious backgrounded process and its parent process to halt any ongoing malicious activity.
* Conduct a thorough review of the affected system’s process tree to identify any additional suspicious or unauthorized processes that may have been spawned.
* Analyze the command history and script files associated with the unusual parent process to understand the scope and intent of the activity.
* Restore the system from a known good backup if any malicious modifications or persistence mechanisms are identified.
* Update and patch the system to close any vulnerabilities that may have been exploited by the adversary.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_906]

**Setup**

This rule requires data coming in from one of the following integrations: - Elastic Defend

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


## Rule query [_rule_query_4959]

```js
event.category:process and host.os.type:linux and event.type:start and
event.action:(ProcessRollup2 or exec or exec_event or start) and
process.name:(bash or csh or dash or fish or ksh or sh or tcsh or zsh) and
process.args:(-c and *&)
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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hide Artifacts
    * ID: T1564
    * Reference URL: [https://attack.mitre.org/techniques/T1564/](https://attack.mitre.org/techniques/T1564/)



