---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-linux-user-added-to-privileged-group.html
---

# Linux User Added to Privileged Group [prebuilt-rule-8-17-3-linux-user-added-to-privileged-group]

Identifies attempts to add a user to a privileged group. Attackers may add users to a privileged group in order to establish persistence on a system.

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

**References**:

* [https://www.elastic.co/security-labs/primer-on-persistence-mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Endgame
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3937]

**Triage and analysis**

**Investigating Linux User User Added to Privileged Group**

The `usermod`, `adduser`, and `gpasswd` commands can be used to assign user accounts to new groups in Linux-based operating systems.

Attackers may add users to a privileged group in order to escalate privileges or establish persistence on a system or domain.

This rule identifies the usages of `usermod`, `adduser` and `gpasswd` to assign user accounts to a privileged group.

[TBC: QUOTE]
**Possible investigation steps**

* Investigate whether the user was succesfully added to the privileged group.
* `!{osquery{"label":"Osquery - Retrieve Information for a Specific User","query":"SELECT * FROM users WHERE username = {user.name}"}}`
* Investigate whether the user is currently logged in and active.
* `!{osquery{"label":"Osquery - Investigate the Account Authentication Status","query":"SELECT * FROM logged_in_users WHERE user = {user.name}"}}`
* Retrieve information about the privileged group to which the user was added.
* `!{osquery{"label":"Osquery - Retrieve Information for a Specific Group","query":"SELECT * FROM groups WHERE groupname = {group.name}"}}`
* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence and whether they are located in expected locations.
* !{osquery{"label":"Osquery - Retrieve Running Processes by User","query":"SELECT pid, username, name FROM processes p JOIN users u ON u.uid = p.uid ORDER BY username"}}
* Identify the user account that performed the action and whether it should perform this kind of action.
* Investigate other alerts associated with the user/host during the past 48 hours.

**False positive analysis**

* Adding accounts to a group is a common administrative task, so there is a high chance of the activity being legitimate. Before investigating further, verify that this activity is not benign.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Review the privileges assigned to the involved users to ensure that the least privilege principle is being followed.
* Delete the account that seems to be involved in malicious activity.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_891]

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


## Rule query [_rule_query_4938]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
  process.args in (
    "root", "admin", "wheel", "staff", "sudo","disk", "video", "shadow", "lxc", "lxd"
  ) and
  (
    process.name in ("usermod", "adduser") or
    (process.name == "gpasswd" and process.args in ("-a", "--add", "-M", "--members"))
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create Account
    * ID: T1136
    * Reference URL: [https://attack.mitre.org/techniques/T1136/](https://attack.mitre.org/techniques/T1136/)

* Sub-technique:

    * Name: Local Account
    * ID: T1136.001
    * Reference URL: [https://attack.mitre.org/techniques/T1136/001/](https://attack.mitre.org/techniques/T1136/001/)



