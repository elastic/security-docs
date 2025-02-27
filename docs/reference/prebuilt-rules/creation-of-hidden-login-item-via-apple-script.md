---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/creation-of-hidden-login-item-via-apple-script.html
---

# Creation of Hidden Login Item via Apple Script [creation-of-hidden-login-item-via-apple-script]

Identifies the execution of osascript to create a hidden login item. This may indicate an attempt to persist a malicious program while concealing its presence.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 109

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_239]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Creation of Hidden Login Item via Apple Script**

AppleScript is a scripting language for automating tasks on macOS, including managing login items. Adversaries exploit this by creating hidden login items to maintain persistence without detection. The detection rule identifies suspicious use of `osascript` to create such items, focusing on command patterns that specify hidden attributes, thus flagging potential stealthy persistence attempts.

**Possible investigation steps**

* Review the process details to confirm the presence of *osascript* in the command line, specifically looking for patterns like "login item" and "hidden:true" to verify the alert’s accuracy.
* Investigate the parent process of the *osascript* execution to determine if it was initiated by a legitimate application or a potentially malicious source.
* Check the user account associated with the process to assess whether the activity aligns with typical user behavior or if it suggests unauthorized access.
* Examine recent login items and system logs to identify any new or unusual entries that could indicate persistence mechanisms being established.
* Correlate the event with other security alerts or logs from the same host to identify any related suspicious activities or patterns.
* If possible, retrieve and analyze the AppleScript code executed to understand its purpose and potential impact on the system.

**False positive analysis**

* Legitimate applications or scripts that automate login item management may trigger this rule. Review the process command line details to verify if the application is trusted.
* System administrators or IT management tools might use AppleScript for legitimate configuration tasks. Confirm if the activity aligns with scheduled maintenance or deployment activities.
* Users with advanced scripting knowledge might create custom scripts for personal use. Check if the script is part of a known user workflow and consider excluding it if verified as non-threatening.
* Frequent triggers from the same source could indicate a benign automation process. Implement exceptions for specific scripts or processes after thorough validation to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent potential lateral movement or data exfiltration.
* Terminate the suspicious osascript process identified in the alert to halt any ongoing malicious activity.
* Remove the hidden login item created by the osascript to eliminate the persistence mechanism. This can be done by accessing the user’s login items and deleting any unauthorized entries.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or processes.
* Review system logs and the user’s recent activity to identify any other signs of compromise or related suspicious behavior.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring for osascript usage and login item modifications across the network to detect similar threats in the future.


## Setup [_setup_158]

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


## Rule query [_rule_query_248]

```js
process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name : "osascript" and
 process.command_line : "osascript*login item*hidden:true*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: AppleScript
    * ID: T1059.002
    * Reference URL: [https://attack.mitre.org/techniques/T1059/002/](https://attack.mitre.org/techniques/T1059/002/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Plist File Modification
    * ID: T1647
    * Reference URL: [https://attack.mitre.org/techniques/T1647/](https://attack.mitre.org/techniques/T1647/)



