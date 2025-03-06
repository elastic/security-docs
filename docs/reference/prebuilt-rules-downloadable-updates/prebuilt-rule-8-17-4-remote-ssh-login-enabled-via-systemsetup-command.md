---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-remote-ssh-login-enabled-via-systemsetup-command.html
---

# Remote SSH Login Enabled via systemsetup Command [prebuilt-rule-8-17-4-remote-ssh-login-enabled-via-systemsetup-command]

Detects use of the systemsetup command to enable remote SSH Login.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://documents.trendmicro.com/assets/pdf/XCSSET_Technical_Brief.pdf](https://documents.trendmicro.com/assets/pdf/XCSSET_Technical_Brief.pdf)
* [https://ss64.com/osx/systemsetup.html](https://ss64.com/osx/systemsetup.html)
* [https://support.apple.com/guide/remote-desktop/about-systemsetup-apd95406b8d/mac](https://support.apple.com/guide/remote-desktop/about-systemsetup-apd95406b8d/mac)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4577]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Remote SSH Login Enabled via systemsetup Command**

The `systemsetup` command in macOS is a utility that allows administrators to configure system settings, including enabling remote SSH login, which facilitates remote management and access. Adversaries may exploit this to gain unauthorized access and move laterally within a network. The detection rule identifies suspicious use of `systemsetup` to enable SSH, excluding legitimate administrative tools, by monitoring process execution patterns and arguments.

**Possible investigation steps**

* Review the process execution details to confirm the use of the systemsetup command with the arguments "-setremotelogin" and "on" to ensure the alert is not a false positive.
* Check the parent process of the systemsetup command to identify if it was executed by a known administrative tool or script, excluding /usr/local/jamf/bin/jamf as per the rule.
* Investigate the user account associated with the process execution to determine if it is a legitimate administrator or a potentially compromised account.
* Examine recent login events and SSH access logs on the host to identify any unauthorized access attempts or successful logins following the enabling of remote SSH login.
* Correlate this event with other security alerts or logs from the same host or network segment to identify potential lateral movement or further malicious activity.

**False positive analysis**

* Legitimate administrative tools like Jamf may trigger this rule when enabling SSH for authorized management purposes. To handle this, ensure that the process parent executable path for Jamf is correctly excluded in the detection rule.
* Automated scripts used for system configuration and maintenance might enable SSH as part of their routine operations. Review these scripts and, if verified as safe, add their parent process paths to the exclusion list.
* IT support activities that require temporary SSH access for troubleshooting can also cause false positives. Document these activities and consider scheduling them during known maintenance windows to reduce alerts.
* Security software or management tools that periodically check or modify system settings could inadvertently trigger this rule. Identify these tools and exclude their specific process paths if they are confirmed to be non-threatening.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious or unauthorized SSH sessions that are currently active on the affected system.
* Review and revoke any unauthorized SSH keys or credentials that may have been added to the system.
* Conduct a thorough examination of the system logs to identify any additional unauthorized activities or changes made by the adversary.
* Restore the system to a known good state from a backup taken before the unauthorized SSH access was enabled, if possible.
* Implement network segmentation to limit SSH access to only trusted administrative systems and users.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems have been compromised.


## Setup [_setup_1409]

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


## Rule query [_rule_query_5569]

```js
event.category:process and host.os.type:macos and event.type:(start or process_started) and
 process.name:systemsetup and
 process.args:("-setremotelogin" and on) and
 not process.parent.executable : /usr/local/jamf/bin/jamf
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: SSH
    * ID: T1021.004
    * Reference URL: [https://attack.mitre.org/techniques/T1021/004/](https://attack.mitre.org/techniques/T1021/004/)



