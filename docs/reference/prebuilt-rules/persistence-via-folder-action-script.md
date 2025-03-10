---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/persistence-via-folder-action-script.html
---

# Persistence via Folder Action Script [persistence-via-folder-action-script]

Detects modification of a Folder Action script. A Folder Action script is executed when the folder to which it is attached has items added or removed, or when its window is opened, closed, moved, or resized. Adversaries may abuse this feature to establish persistence by utilizing a malicious script.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Execution
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_620]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Persistence via Folder Action Script**

Folder Action scripts on macOS automate tasks by executing scripts when folder contents change. Adversaries exploit this by attaching malicious scripts to folders, ensuring execution upon folder events, thus achieving persistence. The detection rule identifies suspicious script executions by monitoring specific processes initiated by the UserScriptService, excluding known benign scripts, to flag potential threats.

**Possible investigation steps**

* Review the process details to confirm the execution of a script by checking the process name and arguments, ensuring it matches the suspicious criteria outlined in the detection rule.
* Investigate the parent process, com.apple.foundation.UserScriptService, to understand the context of the script execution and identify any unusual behavior or anomalies.
* Examine the specific folder associated with the Folder Action script to determine if it has been modified recently or contains any unauthorized or unexpected scripts.
* Check the user account associated with the script execution to verify if the activity aligns with normal user behavior or if it indicates potential compromise.
* Look for any additional related alerts or logs that might provide further context or evidence of malicious activity, such as other script executions or file modifications around the same time.

**False positive analysis**

* Scripts associated with legitimate applications like iTerm2 and Microsoft Office may trigger alerts. These are known benign scripts and can be excluded by adding their paths to the exception list in the detection rule.
* Custom user scripts that automate routine tasks might be flagged. Users should review these scripts and, if verified as safe, add their specific paths to the exclusion criteria.
* Development environments that frequently execute scripts for testing purposes can cause false positives. Developers should ensure that these scripts are executed in a controlled environment and consider excluding their paths if they are consistently flagged.
* System maintenance scripts that are scheduled to run during folder events might be detected. Users should verify these scripts' legitimacy and exclude them if they are part of regular system operations.
* Backup or synchronization tools that use scripts to manage file changes in folders could be mistakenly identified. Confirm these tools' activities and exclude their script paths if they are part of trusted operations.

**Response and remediation**

* Isolate the affected system from the network to prevent further execution of the malicious script and potential lateral movement.
* Terminate any suspicious processes identified by the detection rule, particularly those initiated by the UserScriptService that match the query criteria.
* Remove or disable the malicious Folder Action script from the affected folder to prevent future execution.
* Conduct a thorough review of the affected system’s folder action scripts to identify and remove any additional unauthorized or suspicious scripts.
* Restore any affected files or system components from a known good backup to ensure system integrity.
* Monitor the system for any signs of re-infection or further suspicious activity, focusing on processes and scripts similar to those identified in the alert.
* Escalate the incident to the security team for further investigation and to determine if additional systems are affected, ensuring a comprehensive response to the threat.


## Setup [_setup_401]

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


## Rule query [_rule_query_662]

```js
process where host.os.type == "macos" and event.type : "start" and process.name in ("osascript", "python", "tcl", "node", "perl", "ruby", "php", "bash", "csh", "zsh", "sh") and
  process.parent.name == "com.apple.foundation.UserScriptService" and not process.args : ("/Users/*/Library/Application Support/iTerm2/Scripts/AutoLaunch/*.scpt", "/Users/*/Library/Application Scripts/com.microsoft.*/FoxitUtils.applescript")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Initialization Scripts
    * ID: T1037
    * Reference URL: [https://attack.mitre.org/techniques/T1037/](https://attack.mitre.org/techniques/T1037/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)



