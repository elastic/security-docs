---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-code-execution-via-postgresql.html
---

# Potential Code Execution via Postgresql [prebuilt-rule-8-17-4-potential-code-execution-via-postgresql]

This rule monitors for suspicious activities that may indicate an attacker attempting to execute arbitrary code within a PostgreSQL environment. Attackers can execute code via PostgreSQL as a result of gaining unauthorized access to a public facing PostgreSQL database or exploiting vulnerabilities, such as remote command execution and SQL injection attacks, which can result in unauthorized access and malicious actions, and facilitate post-exploitation activities for unauthorized access and malicious actions.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

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
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4407]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Code Execution via Postgresql**

PostgreSQL, a robust open-source database system, can be exploited by attackers to execute arbitrary code if they gain unauthorized access or exploit vulnerabilities like SQL injection. Adversaries may leverage command execution capabilities to perform malicious actions. The detection rule identifies suspicious processes initiated by the PostgreSQL user, focusing on shell executions that resemble command injection patterns, while excluding legitimate operations, to flag potential threats.

**Possible investigation steps**

* Review the process details to confirm the presence of suspicious shell executions by the PostgreSQL user, focusing on processes with arguments containing "**sh" and "echo**".
* Check the parent process information to determine if the process was initiated by a known legitimate service, such as "puppet", or if it includes "BECOME-SUCCESS-" in the command line, which are excluded from the rule.
* Investigate the source of the PostgreSQL access to identify if it originated from an unauthorized or unusual IP address or user account.
* Analyze the timeline of events leading up to and following the alert to identify any patterns or additional suspicious activities that may indicate a broader attack.
* Correlate the alert with other security events or logs from the same host or network segment to assess if there are related indicators of compromise or ongoing threats.

**False positive analysis**

* Puppet processes may trigger false positives due to their legitimate use of shell commands. To mitigate this, ensure that puppet-related processes are excluded by verifying that process.parent.name is set to "puppet".
* Automation tools that use shell scripts for configuration management might be flagged. Review and exclude these by checking for specific command patterns that are known to be safe, such as those containing "BECOME-SUCCESS".
* Scheduled maintenance scripts executed by the postgres user could be misidentified as threats. Identify these scripts and add them to an exclusion list based on their command line patterns.
* Regular database backup operations that involve shell commands might be mistakenly flagged. Document these operations and exclude them by matching their specific command line arguments.
* Custom monitoring scripts that execute shell commands under the postgres user should be reviewed and excluded if they are verified as non-malicious.

**Response and remediation**

* Immediately isolate the affected PostgreSQL server from the network to prevent further unauthorized access or malicious actions.
* Terminate any suspicious processes identified by the detection rule to halt potential malicious activities.
* Conduct a thorough review of the PostgreSQL server logs to identify any unauthorized access attempts or successful exploitations, focusing on the timeframes around the detected events.
* Reset credentials for the PostgreSQL user and any other potentially compromised accounts to prevent further unauthorized access.
* Apply the latest security patches and updates to the PostgreSQL server to mitigate known vulnerabilities that could be exploited.
* Implement network segmentation to limit access to the PostgreSQL server, ensuring only authorized systems and users can connect.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_1251]

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


## Rule query [_rule_query_5399]

```js
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "fork", "fork_event") and user.name == "postgres" and (
  (process.parent.args : "*sh" and process.parent.args : "echo*") or
  (process.args : "*sh" and process.args : "echo*")
) and not (
  process.parent.name == "puppet" or
  process.command_line like (
    "*BECOME-SUCCESS-*", "bash -c while true; do sleep 1;*", "df -l", "sleep 1", "who", "head -v -n *", "tail -v -n *",
    "/bin/sh -c echo BECOME-SUCCESS*", "/usr/bin/python3 /var/tmp/ansible-tmp*"
  ) or
  process.parent.command_line like "*BECOME-SUCCESS-*"
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

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)



