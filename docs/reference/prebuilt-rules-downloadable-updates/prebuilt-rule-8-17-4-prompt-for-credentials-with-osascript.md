---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-prompt-for-credentials-with-osascript.html
---

# Prompt for Credentials with OSASCRIPT [prebuilt-rule-8-17-4-prompt-for-credentials-with-osascript]

Identifies the use of osascript to execute scripts via standard input that may prompt a user with a rogue dialog for credentials.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/EmpireProject/EmPyre/blob/master/lib/modules/collection/osx/prompt.py](https://github.com/EmpireProject/EmPyre/blob/master/lib/modules/collection/osx/prompt.py)
* [https://ss64.com/osx/osascript.html](https://ss64.com/osx/osascript.md)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4553]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Prompt for Credentials with OSASCRIPT**

OSASCRIPT is a macOS utility that allows the execution of AppleScript and other OSA language scripts. Adversaries may exploit it to display deceptive dialogs prompting users for credentials, mimicking legitimate requests. The detection rule identifies suspicious OSASCRIPT usage by monitoring specific command patterns and excluding known legitimate processes, thereby flagging potential credential theft attempts.

**Possible investigation steps**

* Review the process command line to confirm if the osascript command includes suspicious patterns like "display dialog" with "password" or "passphrase" to determine if it is attempting to prompt for credentials.
* Check the parent process executable to see if it matches any known legitimate applications or services, such as those listed in the exclusion criteria, to rule out false positives.
* Investigate the user account associated with the process to determine if it is a privileged account or if there is any unusual activity associated with it.
* Examine the process execution context, including the effective parent executable, to identify if the osascript was executed by a legitimate management tool or script.
* Look for any other related alerts or logs around the same timeframe to identify if this is part of a broader attack or isolated incident.
* Assess the risk and impact by determining if any credentials were potentially compromised and if further containment or remediation actions are necessary.

**False positive analysis**

* Legitimate administrative scripts using osascript may trigger alerts if they include dialog prompts for passwords or passphrases. To manage this, identify and exclude these scripts by adding their specific command lines or parent executables to the exception list.
* Processes initiated by trusted applications like JAMF or Karabiner-Elements can be mistakenly flagged. Ensure these applications are included in the exclusion list to prevent unnecessary alerts.
* Scheduled maintenance tasks that use osascript for legitimate purposes might be misidentified. Review and exclude these tasks by specifying their user IDs or command line patterns in the detection rule exceptions.
* Custom scripts executed by system administrators for routine operations may appear suspicious. Document these scripts and add them to the exclusion criteria to avoid false positives.
* Terminal-based automation tools that interact with osascript could be incorrectly flagged. Verify these tools and include their paths in the exclusion list to reduce false alerts.

**Response and remediation**

* Immediately isolate the affected macOS device from the network to prevent further unauthorized access or data exfiltration.
* Terminate the suspicious osascript process identified by the alert to stop any ongoing credential theft attempts.
* Conduct a thorough review of the affected system’s recent activity logs to identify any unauthorized access or changes made during the incident.
* Reset credentials for any accounts that may have been compromised, ensuring that new passwords are strong and unique.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be affected.
* Implement additional monitoring on the affected system and similar endpoints to detect any recurrence of the threat.
* Review and update endpoint security configurations to block unauthorized script execution and enhance detection capabilities for similar threats in the future.


## Setup [_setup_1385]

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


## Rule query [_rule_query_5545]

```js
process where event.action == "exec" and host.os.type == "macos" and
 process.name : "osascript" and process.args : "-e" and process.command_line : ("*osascript*display*dialog*password*", "*osascript*display*dialog*passphrase*") and
 not (process.parent.executable : "/usr/bin/sudo" and process.command_line : "*Encryption Key Escrow*") and
 not (process.command_line : "*-e with timeout of 3600 seconds*" and user.id == "0" and process.parent.executable : "/bin/bash") and
 not process.Ext.effective_parent.executable : ("/usr/local/jamf/*",
                                                "/Applications/Karabiner-Elements.app/Contents/MacOS/Karabiner-Elements",
                                                "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                                                "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon",
                                                "/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfManagementService.app/Contents/MacOS/JamfManagementService")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Input Capture
    * ID: T1056
    * Reference URL: [https://attack.mitre.org/techniques/T1056/](https://attack.mitre.org/techniques/T1056/)

* Sub-technique:

    * Name: GUI Input Capture
    * ID: T1056.002
    * Reference URL: [https://attack.mitre.org/techniques/T1056/002/](https://attack.mitre.org/techniques/T1056/002/)



