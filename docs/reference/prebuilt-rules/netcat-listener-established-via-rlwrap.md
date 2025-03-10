---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/netcat-listener-established-via-rlwrap.html
---

# Netcat Listener Established via rlwrap [netcat-listener-established-via-rlwrap]

Monitors for the execution of a netcat listener via rlwrap. rlwrap is a *readline wrapper*, a small utility that uses the GNU Readline library to allow the editing of keyboard input for any command. This utility can be used in conjunction with netcat to gain a more stable reverse shell.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
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
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_570]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Netcat Listener Established via rlwrap**

Netcat, a versatile networking tool, can establish connections for data transfer or remote shell access. When combined with rlwrap, which enhances command-line input, it can create a more stable reverse shell environment. Adversaries exploit this to maintain persistent access. The detection rule identifies such misuse by monitoring rlwrap’s execution with netcat-related arguments, signaling potential unauthorized activity.

**Possible investigation steps**

* Review the process execution details to confirm the presence of rlwrap with netcat-related arguments by examining the process.name and process.args fields.
* Check the process start time and correlate it with any known scheduled tasks or user activity to determine if the execution was expected or authorized.
* Investigate the source IP address and port used in the netcat connection to identify potential external connections or data exfiltration attempts.
* Analyze the user account associated with the process execution to verify if the account has a history of similar activities or if it has been compromised.
* Examine any related network traffic logs to identify unusual patterns or connections that coincide with the alert, focusing on the host where the process was executed.
* Look for any additional processes spawned by the netcat listener to detect further malicious activity or persistence mechanisms.

**False positive analysis**

* Development and testing environments may frequently use rlwrap with netcat for legitimate purposes, such as testing network applications or scripts. To manage this, create exceptions for specific user accounts or IP addresses known to be involved in development activities.
* System administrators might use rlwrap with netcat for troubleshooting or network diagnostics. Identify and exclude these activities by setting up rules that recognize the specific command patterns or user roles associated with administrative tasks.
* Automated scripts or cron jobs that utilize rlwrap and netcat for routine maintenance or monitoring can trigger false positives. Review and whitelist these scripts by their unique process identifiers or command structures to prevent unnecessary alerts.
* Educational or training environments where rlwrap and netcat are used for learning purposes can generate alerts. Implement exceptions based on the environment’s network segment or user group to reduce noise from these benign activities.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or data exfiltration.
* Terminate the rlwrap and netcat processes on the affected host to disrupt the reverse shell connection.
* Conduct a forensic analysis of the affected system to identify any additional malicious activities or persistence mechanisms.
* Review and secure any compromised accounts or credentials that may have been used or accessed during the incident.
* Apply security patches and updates to the affected system to mitigate any exploited vulnerabilities.
* Enhance monitoring and logging on the affected host and network to detect similar activities in the future.
* Report the incident to the appropriate internal security team or external authorities if required, following organizational protocols.


## Setup [_setup_369]

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
* We suggest to select "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_611]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  process.name == "rlwrap" and process.args in ("nc", "ncat", "netcat", "nc.openbsd", "socat") and
  process.args : "*l*" and process.args_count >= 4
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



