---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-admin-group-account-addition.html
---

# Potential Admin Group Account Addition [potential-admin-group-account-addition]

Identifies attempts to add an account to the admin group via the command line. This could be an indication of privilege escalation activity.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://managingosx.wordpress.com/2010/01/14/add-a-user-to-the-admin-group-via-command-line-3-0/](https://managingosx.wordpress.com/2010/01/14/add-a-user-to-the-admin-group-via-command-line-3-0/)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_647]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Admin Group Account Addition**

In macOS environments, tools like `dscl` and `dseditgroup` manage user group memberships, including admin groups. Adversaries may exploit these tools to escalate privileges by adding accounts to admin groups, gaining unauthorized access. The detection rule identifies such attempts by monitoring process activities related to these tools, excluding legitimate management services, to flag potential privilege escalation.

**Possible investigation steps**

* Review the process details to confirm the use of `dscl` or `dseditgroup` with arguments indicating an attempt to add an account to the admin group, such as "/Groups/admin" and "-a" or "-append".
* Check the process’s parent executable path to ensure it is not one of the legitimate management services excluded in the query, such as JamfDaemon, JamfManagementService, jumpcloud-agent, or Addigy go-agent.
* Investigate the user account associated with the process to determine if it has a history of legitimate administrative actions or if it appears suspicious.
* Examine recent login events and user activity on the host to identify any unusual patterns or unauthorized access attempts.
* Correlate the alert with other security events or logs from the same host to identify any related suspicious activities or potential indicators of compromise.
* Assess the risk and impact of the account addition by determining if the account has been successfully added to the admin group and if any unauthorized changes have been made.

**False positive analysis**

* Legitimate management services like JAMF and JumpCloud may trigger false positives when they manage user group memberships. These services are already excluded in the rule, but ensure any additional management tools used in your environment are similarly excluded.
* Automated scripts or maintenance tasks that require temporary admin access might be flagged. Review these scripts and consider adding them to the exclusion list if they are verified as safe.
* System updates or software installations that modify group memberships could be misidentified. Monitor these activities and adjust the rule to exclude known update processes if they are consistently flagged.
* User-initiated actions that are part of normal IT operations, such as adding a new admin for legitimate purposes, may appear as false positives. Ensure that such actions are documented and communicated to avoid unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized access or privilege escalation.
* Review the process execution logs to confirm unauthorized use of `dscl` or `dseditgroup` for adding accounts to the admin group, ensuring the activity is not part of legitimate administrative tasks.
* Remove any unauthorized accounts from the admin group to restore proper access controls and prevent further misuse of elevated privileges.
* Conduct a thorough review of all admin group memberships on the affected system to ensure no other unauthorized accounts have been added.
* Reset passwords for any accounts that were added to the admin group without authorization to prevent further unauthorized access.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and alerting for similar activities across the network to detect and respond to future privilege escalation attempts promptly.


## Setup [_setup_413]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a macOS System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, for MacOS it is recommended to select "Traditional Endpoints".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_689]

```js
event.category:process and host.os.type:macos and event.type:(start or process_started) and
 process.name:(dscl or dseditgroup) and process.args:(("/Groups/admin" or admin) and ("-a" or "-append")) and
 not process.Ext.effective_parent.executable : ("/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon" or
                                                "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfManagementService.app/Contents/MacOS/JamfManagementService" or
                                                "/opt/jc/bin/jumpcloud-agent" or
                                                "/Library/Addigy/go-agent")
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



