---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-reverse-shell-via-background-process.html
---

# Potential Reverse Shell via Background Process [prebuilt-rule-8-17-4-potential-reverse-shell-via-background-process]

Monitors for the execution of background processes with process arguments capable of opening a socket in the /dev/tcp channel. This may indicate the creation of a backdoor reverse connection, and should be investigated further.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

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
* Data Source: Elastic Endgame
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4410]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Reverse Shell via Background Process**

In Linux environments, background processes can be manipulated to establish reverse shells, allowing adversaries to gain remote access. By exploiting shell commands to open network sockets, attackers can create backdoor connections. The detection rule identifies suspicious executions of background processes, like *setsid* or *nohup*, with arguments indicating socket activity in */dev/tcp*, often initiated by common shell interpreters. This helps in flagging potential reverse shell activities for further investigation.

**Possible investigation steps**

* Review the process details to confirm the presence of suspicious arguments, specifically looking for */dev/tcp* in the process.args field, which indicates an attempt to open a network socket.
* Identify the parent process by examining the process.parent.name field to determine if it is one of the common shell interpreters like *bash*, *dash*, *sh*, etc., which could suggest a script-based execution.
* Check the user context under which the process was executed to assess if it aligns with expected user behavior or if it indicates potential compromise of a user account.
* Investigate the network activity associated with the host to identify any unusual outbound connections that could correlate with the reverse shell attempt.
* Correlate the event with other security alerts or logs from the same host to identify any preceding or subsequent suspicious activities that might indicate a broader attack pattern.
* Review historical data for similar process executions on the host to determine if this is an isolated incident or part of a recurring pattern.

**False positive analysis**

* Legitimate administrative scripts may use background processes with network socket activity for maintenance tasks. Review the script’s purpose and source to determine if it is authorized.
* Automated monitoring tools might execute commands that match the rule’s criteria. Identify these tools and consider excluding their specific process names or paths from the rule.
* Development environments often run test scripts that open network connections. Verify the development context and exclude known development-related processes to reduce noise.
* Backup or synchronization software may use similar techniques to transfer data. Confirm the software’s legitimacy and add exceptions for its processes if necessary.
* System updates or package management tools might trigger alerts when installing or updating software. Monitor these activities and whitelist trusted update processes.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious background processes identified by the alert, specifically those involving *setsid* or *nohup* with */dev/tcp* in their arguments.
* Conduct a thorough review of the affected system’s process and network activity logs to identify any additional indicators of compromise or lateral movement.
* Reset credentials for any accounts that were active on the affected system to prevent unauthorized access using potentially compromised credentials.
* Apply security patches and updates to the affected system to address any vulnerabilities that may have been exploited.
* Implement network segmentation to limit the ability of compromised systems to communicate with critical infrastructure or sensitive data repositories.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.


## Setup [_setup_1254]

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


## Rule query [_rule_query_5402]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  process.name in ("setsid", "nohup") and process.args : "*/dev/tcp/*0>&1*" and
  process.parent.name in ("bash", "dash", "sh", "tcsh", "csh", "zsh", "ksh", "fish")
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



