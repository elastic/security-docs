---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/creation-of-hidden-launch-agent-or-daemon.html
---

# Creation of Hidden Launch Agent or Daemon [creation-of-hidden-launch-agent-or-daemon]

Identifies the creation of a hidden launch agent or daemon. An adversary may establish persistence by installing a new launch agent or daemon which executes at login.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.md)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_238]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Creation of Hidden Launch Agent or Daemon**

Launch agents and daemons in macOS are background services that start at login or system boot, respectively, to perform various tasks. Adversaries exploit this by creating hidden agents or daemons to maintain persistence and evade defenses. The detection rule identifies suspicious creation of these services by monitoring specific system paths for new entries, alerting analysts to potential unauthorized persistence mechanisms.

**Possible investigation steps**

* Review the file path of the newly created launch agent or daemon to determine if it matches any known legitimate software installations or updates.
* Check the file creation timestamp to correlate with any recent user activities or system changes that might explain the creation of the file.
* Investigate the contents of the .plist file to identify the program or script it is set to execute, and assess whether it is a known or potentially malicious application.
* Examine the user account associated with the file path, especially if it is located in a user’s Library directory, to determine if the user has a history of installing unauthorized software.
* Cross-reference the file path and associated executable with threat intelligence sources to identify any known indicators of compromise or malicious behavior.
* Look for any other recent file modifications or creations in the same directory that might indicate additional persistence mechanisms or related malicious activity.

**False positive analysis**

* System or application updates may create or modify launch agents or daemons as part of legitimate processes. Users can monitor update schedules and correlate alerts with known update activities to verify legitimacy.
* Some third-party applications install launch agents or daemons to provide background services or updates. Users should maintain an inventory of installed applications and their expected behaviors to identify benign entries.
* User-created scripts or automation tools might use launch agents or daemons for personal productivity tasks. Users can document and exclude these known scripts from monitoring to reduce noise.
* Administrative tools or security software might create temporary launch agents or daemons during scans or system maintenance. Users should verify the source and purpose of these entries and consider excluding them if they are part of routine operations.
* Regularly review and update exclusion lists to ensure they reflect current system configurations and software installations, minimizing the risk of overlooking new threats.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent potential lateral movement or data exfiltration by the adversary.
* Identify and terminate any suspicious processes associated with the newly created launch agent or daemon using Activity Monitor or command-line tools like `launchctl`.
* Remove the unauthorized launch agent or daemon by deleting the corresponding `.plist` file from the identified path. Ensure the file is not recreated by monitoring the directory for changes.
* Conduct a thorough review of user accounts and permissions on the affected system to ensure no unauthorized accounts or privilege escalations have occurred.
* Restore the system from a known good backup if the integrity of the system is in question and further compromise is suspected.
* Escalate the incident to the security operations team for a deeper forensic analysis to determine the root cause and scope of the intrusion.
* Update and enhance endpoint detection and response (EDR) solutions to improve monitoring and alerting for similar persistence mechanisms in the future.


## Setup [_setup_157]

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


## Rule query [_rule_query_247]

```js
file where host.os.type == "macos" and event.type != "deletion" and
  file.path :
  (
    "/System/Library/LaunchAgents/.*.plist",
    "/Library/LaunchAgents/.*.plist",
    "/Users/*/Library/LaunchAgents/.*.plist",
    "/System/Library/LaunchDaemons/.*.plist",
    "/Library/LaunchDaemons/.*.plist"
  )
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

* Sub-technique:

    * Name: Launch Agent
    * ID: T1543.001
    * Reference URL: [https://attack.mitre.org/techniques/T1543/001/](https://attack.mitre.org/techniques/T1543/001/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Hide Artifacts
    * ID: T1564
    * Reference URL: [https://attack.mitre.org/techniques/T1564/](https://attack.mitre.org/techniques/T1564/)

* Sub-technique:

    * Name: Hidden Files and Directories
    * ID: T1564.001
    * Reference URL: [https://attack.mitre.org/techniques/T1564/001/](https://attack.mitre.org/techniques/T1564/001/)



