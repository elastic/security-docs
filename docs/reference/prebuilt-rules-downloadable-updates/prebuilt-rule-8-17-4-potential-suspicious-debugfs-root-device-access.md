---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-suspicious-debugfs-root-device-access.html
---

# Potential Suspicious DebugFS Root Device Access [prebuilt-rule-8-17-4-potential-suspicious-debugfs-root-device-access]

This rule monitors for the usage of the built-in Linux DebugFS utility to access a disk device without root permissions. Linux users that are part of the "disk" group have sufficient privileges to access all data inside of the machine through DebugFS. Attackers may leverage DebugFS in conjunction with "disk" permissions to read sensitive files owned by root, such as the shadow file, root ssh private keys or other sensitive files that may allow them to further escalate privileges.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#disk-group](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#disk-group)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4532]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Suspicious DebugFS Root Device Access**

DebugFS is a Linux utility that provides a low-level interface to access and manipulate file systems, typically used for debugging purposes. It can be exploited by adversaries with "disk" group privileges to access sensitive files without root permissions, potentially leading to privilege escalation. The detection rule identifies non-root users executing DebugFS on disk devices, flagging potential unauthorized access attempts.

**Possible investigation steps**

* Review the process execution details to identify the non-root user and group involved in the DebugFS execution by examining the user.Ext.real.id and group.Ext.real.id fields.
* Check the command-line arguments (process.args) to determine which specific disk device was accessed and assess if the access was legitimate or necessary for the user’s role.
* Investigate the user’s recent activity and login history to identify any unusual patterns or unauthorized access attempts that might indicate malicious intent.
* Verify the user’s group memberships, particularly focusing on the "disk" group, to understand if the user should have such privileges and if any recent changes were made to their group assignments.
* Examine system logs and other security alerts around the time of the DebugFS execution to identify any correlated suspicious activities or potential indicators of compromise.
* Assess the system for any unauthorized changes or access to sensitive files, such as the shadow file or root SSH keys, which could indicate privilege escalation attempts.

**False positive analysis**

* Non-root system administrators or maintenance scripts may use DebugFS for legitimate disk diagnostics or recovery tasks. To handle this, identify and whitelist specific users or scripts that are known to perform these tasks regularly.
* Automated backup or monitoring tools might invoke DebugFS as part of their operations. Review and exclude these tools by adding their process identifiers or user accounts to an exception list.
* Developers or testers with disk group privileges might use DebugFS during development or testing phases. Establish a policy to document and approve such activities, and exclude these users from triggering alerts.
* Educational or training environments where DebugFS is used for learning purposes can generate false positives. Create exceptions for these environments by specifying the associated user accounts or groups.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Revoke "disk" group privileges from non-essential users to limit access to disk devices and prevent misuse of DebugFS.
* Conduct a thorough review of user accounts and group memberships to ensure only authorized personnel have "disk" group privileges.
* Check for unauthorized access to sensitive files such as the shadow file or root SSH private keys and reset credentials if necessary.
* Monitor for any additional suspicious activity on the affected system and related systems, focusing on privilege escalation attempts.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are compromised.
* Implement enhanced logging and monitoring for DebugFS usage and access to disk devices to detect similar threats in the future.


## Setup [_setup_1364]

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


## Rule query [_rule_query_5524]

```js
process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
process.name == "debugfs" and process.args : "/dev/sd*" and not process.args == "-R" and
not user.Ext.real.id == "0" and not group.Ext.real.id == "0"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Local Accounts
    * ID: T1078.003
    * Reference URL: [https://attack.mitre.org/techniques/T1078/003/](https://attack.mitre.org/techniques/T1078/003/)



