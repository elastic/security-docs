---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-shadow-file-modification-by-unusual-process.html
---

# Shadow File Modification by Unusual Process [prebuilt-rule-8-17-4-shadow-file-modification-by-unusual-process]

This rule monitors for Linux Shadow file modifications. These modifications are indicative of a potential password change or user addition event. Threat actors may attempt to create new users or change the password of a user account to maintain access to a system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*

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
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4487]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Shadow File Modification by Unusual Process**

The Linux shadow file is crucial for storing hashed user passwords, ensuring system security. Adversaries may exploit this by altering the file to add users or change passwords, thus gaining unauthorized access or maintaining persistence. The detection rule identifies suspicious modifications by monitoring changes and renames of the shadow file, flagging potential unauthorized access attempts for further investigation.

**Possible investigation steps**

* Review the alert details to confirm the event type is "change" and the action is "rename" for the file path "/etc/shadow".
* Check the file.Ext.original.path to identify the original location of the shadow file before the rename event.
* Investigate recent user account changes or additions by examining system logs and user management commands executed around the time of the alert.
* Analyze the history of commands executed by users with elevated privileges to identify any unauthorized or suspicious activities.
* Correlate the event with other security alerts or logs to determine if there are additional indicators of compromise or persistence tactics being employed.
* Verify the integrity of the shadow file by comparing its current state with a known good backup to detect unauthorized modifications.

**False positive analysis**

* System updates or package installations may trigger legitimate changes to the shadow file. Users can create exceptions for known update processes or package managers to prevent these from being flagged.
* Administrative tasks performed by authorized personnel, such as password changes or user management, can also result in shadow file modifications. Implementing a whitelist for specific user accounts or processes that are known to perform these tasks can reduce false positives.
* Backup or restoration processes that involve the shadow file might cause rename events. Users should identify and exclude these processes if they are part of regular system maintenance.
* Automated scripts or configuration management tools that manage user accounts could lead to expected changes in the shadow file. Users should ensure these tools are recognized and excluded from triggering alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Verify the integrity of the /etc/shadow file by comparing it with a known good backup to identify unauthorized changes or additions.
* Reset passwords for all user accounts on the affected system, ensuring the use of strong, unique passwords to mitigate the risk of compromised credentials.
* Review and remove any unauthorized user accounts that may have been added to the system, ensuring that only legitimate users have access.
* Conduct a thorough audit of system logs and user activity to identify any additional signs of compromise or persistence mechanisms employed by the threat actor.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be affected.
* Implement enhanced monitoring and alerting for future modifications to the /etc/shadow file to quickly detect and respond to similar threats.


## Setup [_setup_1325]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a Linux System:**

* Go to the Kibana home page and click Add integrations.
* In the query bar, search for Elastic Defend and select the integration to see more details about it.
* Click Add Elastic Defend.
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, either Traditional Endpoints or Cloud Workloads.
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest to select "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in New agent policy name. If other agent policies already exist, you can click the Existing hosts tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click Save and Continue.
* To complete the integration, select Add Elastic Agent to your hosts and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_5479]

```js
file where host.os.type == "linux" and event.type == "change" and event.action == "rename" and
file.path == "/etc/shadow" and file.Ext.original.path != null and
not process.name in (
  "usermod", "useradd", "passwd", "chage", "systemd-sysusers", "chpasswd", "userdel", "adduser", "update-passwd", "perl"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)



