---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/softwareupdate-preferences-modification.html
---

# SoftwareUpdate Preferences Modification [softwareupdate-preferences-modification]

Identifies changes to the SoftwareUpdate preferences using the built-in defaults command. Adversaries may abuse this in an attempt to disable security updates.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.checkpoint.com/2017/07/13/osxdok-refuses-go-away-money/](https://blog.checkpoint.com/2017/07/13/osxdok-refuses-go-away-money/)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_933]

**Triage and analysis**

[TBC: QUOTE]
**Investigating SoftwareUpdate Preferences Modification**

In macOS environments, the SoftwareUpdate preferences manage system updates, crucial for maintaining security. Adversaries may exploit the *defaults* command to alter these settings, potentially disabling updates to evade defenses. The detection rule identifies such modifications by monitoring specific command executions that attempt to change update preferences without enabling them, signaling potential malicious activity.

**Possible investigation steps**

* Review the process execution details to confirm the presence of the *defaults* command with arguments attempting to modify SoftwareUpdate preferences, specifically looking for *write*, *-bool*, and the targeted preferences file paths.
* Check the user account associated with the process execution to determine if it aligns with expected administrative activity or if it might be indicative of unauthorized access.
* Investigate the host’s recent activity for any other suspicious processes or commands that may suggest a broader attempt to impair system defenses or evade detection.
* Examine system logs and security alerts around the time of the detected event to identify any correlated activities or anomalies that could provide additional context or evidence of malicious intent.
* Assess the current state of the SoftwareUpdate preferences on the affected host to verify if updates have been disabled or altered, and take corrective actions if necessary.

**False positive analysis**

* System administrators may use the defaults command to configure SoftwareUpdate settings during routine maintenance. To handle this, create exceptions for known administrative scripts or processes that frequently execute these commands.
* Automated configuration management tools might alter SoftwareUpdate preferences as part of their standard operations. Identify these tools and exclude their process identifiers from triggering the rule.
* Some legitimate applications may require specific update settings and modify preferences accordingly. Monitor and whitelist these applications to prevent unnecessary alerts.
* User-initiated changes to update settings for personal preferences can trigger false positives. Educate users on the implications of such changes and consider excluding user-specific processes if they are consistently non-threatening.
* During system setup or reconfiguration, defaults commands may be used to establish baseline settings. Temporarily disable the rule or set up a temporary exception during these periods to avoid false alerts.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent potential spread or further unauthorized changes.
* Review the process execution logs to confirm the unauthorized use of the *defaults* command and identify any associated user accounts or processes.
* Revert any unauthorized changes to the SoftwareUpdate preferences by resetting them to their default state using the *defaults* command with appropriate parameters.
* Conduct a thorough scan of the affected system for additional signs of compromise, such as malware or unauthorized access attempts, using endpoint security tools.
* Change passwords and review permissions for any user accounts involved in the incident to prevent further unauthorized access.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be affected.
* Implement enhanced monitoring for similar command executions across the network to detect and respond to future attempts promptly.


## Setup [_setup_588]

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


## Rule query [_rule_query_994]

```js
event.category:process and host.os.type:macos and event.type:(start or process_started) and
 process.name:defaults and
 process.args:(write and "-bool" and (com.apple.SoftwareUpdate or /Library/Preferences/com.apple.SoftwareUpdate.plist) and not (TRUE or true))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



