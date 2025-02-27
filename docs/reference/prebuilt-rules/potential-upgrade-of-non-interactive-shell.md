---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-upgrade-of-non-interactive-shell.html
---

# Potential Upgrade of Non-interactive Shell [potential-upgrade-of-non-interactive-shell]

Identifies when a non-interactive terminal (tty) is being upgraded to a fully interactive shell. Attackers may upgrade a simple reverse shell to a fully interactive tty after obtaining initial access to a host, in order to obtain a more stable connection.

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
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_784]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Upgrade of Non-interactive Shell**

In Linux environments, attackers often seek to enhance a basic reverse shell to a fully interactive shell to gain a more robust foothold. This involves using tools like `stty` or `script` to manipulate terminal settings, enabling features like command history and job control. The detection rule identifies such activities by monitoring specific process executions and arguments, flagging potential misuse indicative of an upgrade attempt.

**Possible investigation steps**

* Review the process execution details to confirm the presence of `stty` or `script` commands with the specific arguments outlined in the detection rule, such as `stty raw -echo` or `script -qc /dev/null`.
* Examine the parent process of the flagged `stty` or `script` command to determine how the shell was initially spawned and identify any potentially malicious scripts or binaries.
* Check the user account associated with the process execution to assess if it aligns with expected user behavior or if it indicates potential compromise.
* Investigate the network connections associated with the host at the time of the alert to identify any suspicious remote connections that could be indicative of a reverse shell.
* Review historical process execution and login records for the user and host to identify any patterns of suspicious activity or previous attempts to establish a reverse shell.

**False positive analysis**

* System administrators or legitimate users may use stty or script commands for routine maintenance or troubleshooting, which can trigger the rule. To manage this, create exceptions for known user accounts or specific maintenance windows.
* Automated scripts or cron jobs that utilize stty or script for legitimate purposes might be flagged. Review these scripts and whitelist them by process hash or command line pattern to prevent false positives.
* Development environments where developers frequently use stty or script for testing purposes can generate alerts. Consider excluding specific development machines or user groups from the rule to reduce noise.
* Monitoring tools or security solutions that simulate shell upgrades for testing or auditing purposes may inadvertently trigger the rule. Identify these tools and add them to an exception list based on their process name or execution path.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or lateral movement by the attacker.
* Terminate any suspicious processes identified by the detection rule, specifically those involving `stty` or `script` with the flagged arguments, to disrupt the attacker’s attempt to upgrade the shell.
* Conduct a thorough review of the affected system’s logs and process history to identify any additional malicious activities or compromised accounts.
* Reset credentials for any user accounts that were active during the time of the alert to prevent unauthorized access using potentially compromised credentials.
* Apply security patches and updates to the affected system to address any vulnerabilities that may have been exploited by the attacker.
* Enhance monitoring and logging on the affected host and similar systems to detect any future attempts to upgrade non-interactive shells or other suspicious activities.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems may be affected.


## Setup [_setup_507]

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


## Rule query [_rule_query_832]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  (
    (process.name == "stty" and process.args == "raw" and process.args == "-echo" and process.args_count >= 3) or
    (process.name == "script" and process.args in ("-qc", "-c") and process.args == "/dev/null" and
    process.args_count == 4)
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



