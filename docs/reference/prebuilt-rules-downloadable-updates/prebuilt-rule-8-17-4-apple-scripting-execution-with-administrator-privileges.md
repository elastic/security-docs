---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-apple-scripting-execution-with-administrator-privileges.html
---

# Apple Scripting Execution with Administrator Privileges [prebuilt-rule-8-17-4-apple-scripting-execution-with-administrator-privileges]

Identifies execution of the Apple script interpreter (osascript) without a password prompt and with administrator privileges.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://discussions.apple.com/thread/2266150](https://discussions.apple.com/thread/2266150)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Execution
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4602]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Apple Scripting Execution with Administrator Privileges**

AppleScript, a scripting language for macOS, automates tasks by controlling applications and system functions. Adversaries may exploit it to execute scripts with elevated privileges, bypassing password prompts, to gain unauthorized access or escalate privileges. The detection rule identifies such misuse by monitoring the execution of AppleScript with admin rights, excluding benign parent processes like Electron, to flag potential threats.

**Possible investigation steps**

* Review the process details to confirm the execution of *osascript* with administrator privileges, focusing on the command line arguments to understand the script’s intent.
* Investigate the parent process of *osascript* to determine if it is a known and trusted application, ensuring it is not *Electron* or any other excluded parent processes.
* Check the user account associated with the *osascript* execution to verify if it is a legitimate account and assess if there are any signs of compromise or unauthorized access.
* Analyze recent system logs and user activity to identify any unusual behavior or patterns that coincide with the time of the alert.
* Correlate this event with other security alerts or incidents to determine if it is part of a broader attack or isolated incident.

**False positive analysis**

* Known false positives may arise from legitimate applications that use AppleScript with administrator privileges for valid operations, such as software installers or system management tools.
* Exclude processes with benign parent applications like Electron, as specified in the rule, to reduce false positives from common development environments.
* Consider adding exceptions for other trusted applications that frequently use AppleScript with elevated privileges, ensuring they are verified and necessary for business operations.
* Regularly review and update the list of excluded applications to adapt to changes in software usage and maintain effective threat detection.
* Monitor the frequency and context of alerts to identify patterns that may indicate false positives, adjusting the detection rule as needed to minimize unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious osascript processes running with administrator privileges that were not initiated by known, legitimate applications.
* Review system logs and process execution history to identify any unauthorized changes or access that occurred during the incident.
* Revoke any compromised credentials or accounts that may have been used to execute the AppleScript with elevated privileges.
* Restore the system to a known good state from a backup taken before the unauthorized script execution, if necessary.
* Implement application whitelisting to prevent unauthorized scripts from executing with elevated privileges in the future.
* Escalate the incident to the security operations team for further investigation and to assess the need for additional security controls or monitoring enhancements.


## Setup [_setup_1434]

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


## Rule query [_rule_query_5594]

```js
process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name : "osascript" and
  process.command_line : "osascript*with administrator privileges" and
  not process.parent.name : "Electron" and
  not process.Ext.effective_parent.executable : ("/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
                                                 "/Applications/OpenVPN Connect/Uninstall OpenVPN Connect.app/Contents/MacOS/uninstaller")
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

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)



