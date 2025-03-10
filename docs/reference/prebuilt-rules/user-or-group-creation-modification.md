---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/user-or-group-creation-modification.html
---

# User or Group Creation/Modification [user-or-group-creation-modification]

This rule leverages the `auditd_manager` integration to detect user or group creation or modification events on Linux systems. Threat actors may attempt to create or modify users or groups to establish persistence on the system.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-auditd_manager.auditd-*

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
* Data Source: Auditd Manager
* Resources: Investigation Guide

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1177]

**Triage and analysis**

[TBC: QUOTE]
**Investigating User or Group Creation/Modification**

In Linux environments, user and group management is crucial for access control and system administration. Adversaries may exploit this by creating or modifying accounts to maintain unauthorized access. The detection rule utilizes audit logs to monitor successful user or group changes, flagging potential persistence tactics by correlating specific actions with known threat behaviors.

**Possible investigation steps**

* Review the audit logs to identify the specific user or group account that was created or modified, focusing on the event.action field values such as "changed-password", "added-user-account", or "added-group-account-to".
* Check the timestamp of the event to determine when the account change occurred and correlate it with any other suspicious activities or alerts around the same time.
* Investigate the source of the event by examining the host information, particularly the host.os.type field, to understand which system the changes were made on.
* Identify the user or process that initiated the account change by reviewing the associated user information in the audit logs, which may provide insights into whether the action was authorized or potentially malicious.
* Cross-reference the identified user or group changes with known threat actor behaviors or recent incidents to assess if the activity aligns with any known persistence tactics.

**False positive analysis**

* Routine administrative tasks may trigger alerts when system administrators create or modify user or group accounts as part of regular maintenance. To manage this, consider creating exceptions for known administrative accounts or scheduled maintenance windows.
* Automated scripts or configuration management tools that manage user accounts can generate false positives. Identify these tools and exclude their actions from triggering alerts by whitelisting their processes or user accounts.
* System updates or software installations that require user or group modifications might be flagged. Review the context of these changes and exclude specific update processes or installation scripts from the rule.
* Temporary user accounts created for short-term projects or testing purposes can be mistaken for unauthorized access attempts. Implement a naming convention for temporary accounts and exclude them from the rule to reduce noise.
* Changes made by trusted third-party services or applications that integrate with the system may appear suspicious. Verify these services and add them to an exception list to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Review the audit logs to identify the specific user or group accounts that were created or modified, and disable or remove any unauthorized accounts.
* Reset passwords for any compromised or suspicious accounts to prevent further unauthorized access.
* Conduct a thorough review of system and application logs to identify any additional unauthorized changes or suspicious activities that may have occurred.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems have been compromised.
* Implement additional monitoring on the affected system and similar systems to detect any further unauthorized account activities.
* Review and update access control policies and procedures to prevent similar incidents in the future, ensuring that only authorized personnel have the ability to create or modify user and group accounts.


## Setup [_setup_748]

**Setup**

This rule requires data coming in from Auditd Manager.

**Auditd Manager Integration Setup**

The Auditd Manager Integration receives audit events from the Linux Audit Framework which is a part of the Linux kernel. Auditd Manager provides a user-friendly interface and automation capabilities for configuring and monitoring system auditing through the auditd daemon. With `auditd_manager`, administrators can easily define audit rules, track system events, and generate comprehensive audit reports, improving overall security and compliance in the system.

**The following steps should be executed in order to add the Elastic Agent System integration "auditd_manager" on a Linux System:**

* Go to the Kibana home page and click “Add integrations”.
* In the query bar, search for “Auditd Manager” and select the integration to see more details about it.
* Click “Add Auditd Manager”.
* Configure the integration name and optionally add a description.
* Review optional and advanced settings accordingly.
* Add the newly installed “auditd manager” to an existing or a new agent policy, and deploy the agent on a Linux system from which auditd log files are desirable.
* Click “Save and Continue”.
* For more details on the integration refer to the [helper guide](https://docs.elastic.co/integrations/auditd_manager).

**Rule Specific Setup Note**

Auditd Manager subscribes to the kernel and receives events as they occur without any additional configuration. However, if more advanced configuration is required to detect specific behavior, audit rules can be added to the integration in either the "audit rules" configuration box or the "auditd rule files" box by specifying a file to read the audit rules from. For this detection rule to trigger, the following additional audit rules are required to be added to the integration:

```
-w /usr/sbin/groupadd -p x -k group_modification
-w /sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /sbin/groupmod -p x -k group_modification
-w /usr/sbin/addgroup -p x -k group_modification
-w /sbin/addgroup -p x -k group_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /sbin/usermod -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_modification
-w /sbin/userdel -p x -k user_modification
-w /usr/sbin/useradd -p x -k user_modification
-w /sbin/useradd -p x -k user_modification
-w /usr/sbin/adduser -p x -k user_modification
-w /sbin/adduser -p x -k user_modification
```


## Rule query [_rule_query_1200]

```js
iam where host.os.type == "linux" and event.type in ("creation", "change") and auditd.result == "success" and
event.action in ("changed-password", "added-user-account", "added-group-account-to") and process.name != null
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



