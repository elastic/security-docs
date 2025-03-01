---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-modification-of-safari-settings-via-defaults-command.html
---

# Modification of Safari Settings via Defaults Command [prebuilt-rule-8-17-4-modification-of-safari-settings-via-defaults-command]

Identifies changes to the Safari configuration using the built-in defaults command. Adversaries may attempt to enable or disable certain Safari settings, such as enabling JavaScript from Apple Events to ease in the hijacking of the users browser.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://objectivebythesea.com/v2/talks/OBTS_v2_Zohar.pdf](https://objectivebythesea.com/v2/talks/OBTS_v2_Zohar.pdf)

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

## Investigation guide [_investigation_guide_4563]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Modification of Safari Settings via Defaults Command**

The *defaults* command in macOS is a utility that allows users to read, write, and manage macOS application preferences, including Safari settings. Adversaries may exploit this command to alter Safari configurations, potentially enabling harmful features like JavaScript from Apple Events, which can facilitate browser hijacking. The detection rule monitors for suspicious *defaults* command usage targeting Safari settings, excluding benign preference changes, to identify potential defense evasion attempts.

**Possible investigation steps**

* Review the process execution details to confirm the use of the *defaults* command with arguments targeting Safari settings, specifically looking for any suspicious or unauthorized changes.
* Check the user account associated with the process execution to determine if the action was performed by a legitimate user or an unauthorized entity.
* Investigate the system’s recent activity logs to identify any other unusual or suspicious behavior around the time the *defaults* command was executed.
* Examine the Safari settings before and after the change to assess the impact and identify any potentially harmful configurations, such as enabling JavaScript from Apple Events.
* Correlate the event with other security alerts or incidents to determine if this action is part of a broader attack or compromise attempt.

**False positive analysis**

* Changes to Safari settings for legitimate user preferences can trigger alerts, such as enabling or disabling search suggestions. Users can create exceptions for these specific settings by excluding them from the detection rule.
* System administrators may use the defaults command to configure Safari settings across multiple devices for compliance or user experience improvements. These actions can be whitelisted by identifying the specific process arguments used in these administrative tasks.
* Automated scripts or management tools that adjust Safari settings as part of routine maintenance or updates may cause false positives. Users should identify these scripts and exclude their specific process arguments from the detection rule.
* Developers testing Safari configurations might frequently change settings using the defaults command. Excluding known developer machines or user accounts from the rule can help reduce false positives.
* Educational or training environments where users are instructed to modify Safari settings for learning purposes can lead to alerts. Identifying and excluding these environments or sessions can mitigate unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected macOS device from the network to prevent further malicious activity or data exfiltration.
* Terminate any suspicious processes related to the *defaults* command that are currently running on the affected device.
* Revert any unauthorized changes made to Safari settings by restoring them to their default or previously known safe state.
* Conduct a thorough scan of the affected device using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malware or malicious scripts.
* Review and update the device’s security settings to prevent unauthorized changes, including disabling unnecessary Apple Events and restricting the use of the *defaults* command to authorized personnel only.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if other devices in the network are affected.
* Implement enhanced monitoring and alerting for similar *defaults* command usage across the network to detect and respond to future attempts promptly.


## Setup [_setup_1395]

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


## Rule query [_rule_query_5555]

```js
event.category:process and host.os.type:macos and event.type:start and
  process.name:defaults and process.args:
    (com.apple.Safari and write and not
      (
      UniversalSearchEnabled or
      SuppressSearchSuggestions or
      WebKitTabToLinksPreferenceKey or
      ShowFullURLInSmartSearchField or
      com.apple.Safari.ContentPageGroupIdentifier.WebKit2TabsToLinks
      )
    )
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



