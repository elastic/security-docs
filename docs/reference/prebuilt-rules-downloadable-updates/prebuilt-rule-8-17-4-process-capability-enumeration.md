---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-process-capability-enumeration.html
---

# Process Capability Enumeration [prebuilt-rule-8-17-4-process-capability-enumeration]

Identifies recursive process capability enumeration of the entire filesystem through the getcap command. Malicious users may manipulate identified capabilities to gain root privileges.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-crowdstrike.fdr*

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
* Data Source: Elastic Endgame
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4376]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Process Capability Enumeration**

In Linux environments, the `getcap` command is used to list file capabilities, which define specific privileges for executables. Adversaries may exploit this by recursively scanning the filesystem to identify and manipulate capabilities, potentially escalating privileges. The detection rule identifies suspicious use of `getcap` by monitoring for its execution with specific arguments, especially by non-root users, indicating potential misuse.

**Possible investigation steps**

* Review the alert details to confirm the execution of the `getcap` command with the arguments `-r` and `/`, ensuring the process was initiated by a non-root user (user.id != "0").
* Identify the user account associated with the process execution to determine if the user has a legitimate reason to perform such actions.
* Examine the process execution history for the identified user to check for any other suspicious activities or commands executed around the same time.
* Investigate the system logs for any signs of privilege escalation attempts or unauthorized access following the execution of the `getcap` command.
* Check for any recent changes to file capabilities on the system that could indicate manipulation by the adversary.
* Assess the system for any other indicators of compromise or related alerts that might suggest a broader attack campaign.

**False positive analysis**

* System administrators or automated scripts may use the getcap command for legitimate auditing purposes. To handle this, create exceptions for known administrative accounts or scripts that regularly perform capability checks.
* Security tools or monitoring solutions might trigger the rule during routine scans. Identify these tools and exclude their processes from triggering alerts by adding them to an allowlist.
* Developers or testing environments may execute getcap as part of software testing or development processes. Exclude specific user IDs or groups associated with these environments to prevent unnecessary alerts.
* Scheduled maintenance tasks might involve capability enumeration. Document and exclude these tasks by specifying the time frames or user accounts involved in the maintenance activities.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further exploitation or lateral movement by the adversary.
* Terminate any unauthorized or suspicious processes associated with the `getcap` command to halt potential privilege escalation activities.
* Conduct a thorough review of the system’s file capabilities using a trusted method to identify any unauthorized changes or suspicious capabilities that may have been set.
* Revert any unauthorized capability changes to their original state to ensure that no elevated privileges are retained by malicious users.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Implement monitoring for similar `getcap` command executions across the environment to detect and respond to future attempts promptly.
* Review and update access controls and user permissions to ensure that only authorized users have the necessary privileges to execute potentially sensitive commands like `getcap`.


## Setup [_setup_1223]

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


## Rule query [_rule_query_5368]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "ProcessRollup2") and
  process.name == "getcap" and process.args == "-r" and process.args == "/" and
  process.args_count == 3 and user.id != "0"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Process Discovery
    * ID: T1057
    * Reference URL: [https://attack.mitre.org/techniques/T1057/](https://attack.mitre.org/techniques/T1057/)



