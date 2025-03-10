---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-attempt-to-clear-kernel-ring-buffer.html
---

# Attempt to Clear Kernel Ring Buffer [prebuilt-rule-8-17-4-attempt-to-clear-kernel-ring-buffer]

Monitors for the deletion of the kernel ring buffer events through dmesg. Attackers may clear kernel ring buffer events to evade detection after installing a Linux kernel module (LKM).

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
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
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4334]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Attempt to Clear Kernel Ring Buffer**

The kernel ring buffer logs system messages, crucial for diagnosing issues. Adversaries may clear these logs using the `dmesg -c` command to hide traces of malicious activities, such as installing unauthorized kernel modules. The detection rule identifies this behavior by monitoring the execution of `dmesg` with specific arguments, flagging potential evasion attempts for further investigation.

**Possible investigation steps**

* Review the process execution details to confirm the presence of the `dmesg -c` command, focusing on the process name and arguments to ensure the alert is valid.
* Investigate the user account associated with the execution of the `dmesg -c` command to determine if it is a known and authorized user or potentially compromised.
* Check for any recent installations or modifications of Linux kernel modules (LKMs) on the host to identify unauthorized changes that may coincide with the log clearing attempt.
* Examine other system logs and security alerts around the same timeframe to identify any suspicious activities or patterns that may indicate a broader attack or compromise.
* Assess the host’s network activity for any unusual outbound connections or data exfiltration attempts that could suggest further malicious intent.

**False positive analysis**

* Routine system maintenance activities may trigger the rule if administrators use the dmesg -c command to clear logs for legitimate purposes. To handle this, create exceptions for known maintenance scripts or processes that regularly execute this command.
* Automated scripts or monitoring tools that include dmesg -c as part of their log management routine can cause false positives. Identify these scripts and exclude them from the rule by specifying their process IDs or user accounts.
* Development and testing environments where kernel modules are frequently installed and removed might generate alerts. Consider excluding these environments from the rule or adjusting the risk score to reflect the lower threat level in these contexts.
* System administrators may use dmesg -c during troubleshooting to clear logs and view new messages. Document these activities and create exceptions for specific user accounts or roles that perform this task regularly.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity or lateral movement.
* Conduct a thorough review of the system to identify any unauthorized kernel modules or other suspicious changes, and remove them if found.
* Restore the system from a known good backup if unauthorized changes are detected and cannot be easily reversed.
* Review and update access controls and permissions to ensure that only authorized users have the ability to execute commands like `dmesg -c`.
* Implement enhanced monitoring and logging for the affected system to detect any future attempts to clear the kernel ring buffer or similar evasion tactics.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Conduct a post-incident review to identify gaps in detection and response, and update security policies and procedures to prevent recurrence.


## Setup [_setup_1183]

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


## Rule query [_rule_query_5326]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started")
 and process.name == "dmesg" and process.args in ("-c", "--clear")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)

* Sub-technique:

    * Name: Clear Linux or Mac System Logs
    * ID: T1070.002
    * Reference URL: [https://attack.mitre.org/techniques/T1070/002/](https://attack.mitre.org/techniques/T1070/002/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



