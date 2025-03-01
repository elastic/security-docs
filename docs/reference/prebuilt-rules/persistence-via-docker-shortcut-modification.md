---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/persistence-via-docker-shortcut-modification.html
---

# Persistence via Docker Shortcut Modification [persistence-via-docker-shortcut-modification]

An adversary can establish persistence by modifying an existing macOS dock property list in order to execute a malicious application instead of the intended one when invoked.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/specterops/presentations/raw/master/Leo%20Pitt/Hey_Im_Still_in_Here_Modern_macOS_Persistence_SO-CON2020.pdf](https://github.com/specterops/presentations/raw/master/Leo%20Pitt/Hey_Im_Still_in_Here_Modern_macOS_Persistence_SO-CON2020.pdf)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_619]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Persistence via Docker Shortcut Modification**

Docker shortcuts on macOS are managed through dock property lists, which define application launch behaviors. Adversaries may exploit this by altering these lists to redirect shortcuts to malicious applications, thus achieving persistence. The detection rule identifies unauthorized modifications to these property lists, excluding legitimate processes, to flag potential threats. This approach helps in pinpointing suspicious activities that could indicate persistence mechanisms being established by attackers.

**Possible investigation steps**

* Review the alert details to identify the specific file path and process name involved in the modification of the com.apple.dock.plist file.
* Examine the process that triggered the alert by checking its parent process, command line arguments, and execution history to determine if it is associated with known malicious activity.
* Investigate the user account associated with the file modification to determine if there are any signs of compromise or unauthorized access.
* Check for any recent changes or anomalies in the user’s environment, such as new applications installed or unexpected network connections, that could indicate further malicious activity.
* Correlate the event with other security alerts or logs from the same host to identify any patterns or additional indicators of compromise.
* If possible, restore the original com.apple.dock.plist file from a backup to ensure the system’s integrity and prevent the execution of any malicious applications.

**False positive analysis**

* Legitimate software updates or installations may modify the dock property list. Users can create exceptions for known update processes like software management tools to prevent false alerts.
* System maintenance tasks performed by macOS utilities might trigger the rule. Exclude processes such as cfprefsd and plutil, which are involved in regular system operations, to reduce noise.
* Custom scripts or automation tools that modify user preferences could be flagged. Identify and whitelist these scripts if they are part of routine administrative tasks.
* Security or IT management tools like Jamf or Kandji may interact with dock property lists. Ensure these tools are included in the exclusion list to avoid unnecessary alerts.
* User-initiated changes to dock settings can also be mistaken for malicious activity. Educate users on the implications of modifying dock settings and monitor for patterns that deviate from normal behavior.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further malicious activity or lateral movement.
* Terminate any suspicious processes identified as modifying the dock property list, especially those not matching legitimate process names or executables.
* Restore the original com.apple.dock.plist file from a known good backup to ensure the dock shortcuts are not redirecting to malicious applications.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection tools to identify and remove any additional malicious software.
* Review and audit user accounts and permissions on the affected system to ensure no unauthorized access or privilege escalation has occurred.
* Implement monitoring for any future unauthorized modifications to dock property lists, ensuring alerts are configured for quick response.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be affected.


## Setup [_setup_400]

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


## Rule query [_rule_query_661]

```js
event.category:file and host.os.type:macos and event.action:modification and
 file.path:/Users/*/Library/Preferences/com.apple.dock.plist and
 not process.name:(xpcproxy or cfprefsd or plutil or jamf or PlistBuddy or InstallerRemotePluginService) and
 not process.executable:(/Library/Addigy/download-cache/* or "/Library/Kandji/Kandji Agent.app/Contents/MacOS/kandji-library-manager")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)



