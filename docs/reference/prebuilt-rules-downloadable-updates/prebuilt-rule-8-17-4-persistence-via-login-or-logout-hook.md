---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-persistence-via-login-or-logout-hook.html
---

# Persistence via Login or Logout Hook [prebuilt-rule-8-17-4-persistence-via-login-or-logout-hook]

Identifies use of the Defaults command to install a login or logoff hook in MacOS. An adversary may abuse this capability to establish persistence in an environment by inserting code to be executed at login or logout.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.virusbulletin.com/uploads/pdf/conference_slides/2014/Wardle-VB2014.pdf](https://www.virusbulletin.com/uploads/pdf/conference_slides/2014/Wardle-VB2014.pdf)
* [https://www.manpagez.com/man/1/defaults/](https://www.manpagez.com/man/1/defaults/)

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

## Investigation guide [_investigation_guide_4594]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Persistence via Login or Logout Hook**

In macOS environments, login and logout hooks are scripts executed automatically during user login or logout, often used for system management tasks. Adversaries exploit this by inserting malicious scripts to maintain persistence. The detection rule identifies suspicious use of the `defaults` command to set these hooks, excluding known legitimate scripts, thus highlighting potential unauthorized persistence attempts.

**Possible investigation steps**

* Review the process execution details to confirm the use of the "defaults" command with "write" arguments targeting "LoginHook" or "LogoutHook".
* Check the process execution history for the user account associated with the alert to identify any unusual or unauthorized activity.
* Investigate the source and content of the script specified in the "defaults" command to determine if it contains malicious or unauthorized code.
* Cross-reference the script path against known legitimate scripts to ensure it is not mistakenly flagged.
* Analyze recent system changes or installations that might have introduced the suspicious script or process.
* Review system logs around the time of the alert for any additional indicators of compromise or related suspicious activity.

**False positive analysis**

* Known false positives include legitimate scripts used by system management tools like JAMF, which are often set as login or logout hooks.
* To handle these, users can create exceptions for known legitimate scripts by adding their paths to the exclusion list in the detection rule.
* Regularly review and update the exclusion list to ensure it includes all authorized scripts used in your environment.
* Monitor for any changes in the behavior of these scripts to ensure they remain non-threatening and authorized.
* Collaborate with IT and security teams to identify any new legitimate scripts that should be excluded from detection.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent potential lateral movement or data exfiltration by the adversary.
* Terminate any suspicious processes associated with the unauthorized login or logout hooks to halt any ongoing malicious activity.
* Remove the unauthorized login or logout hooks by using the `defaults delete` command to ensure the persistence mechanism is dismantled.
* Conduct a thorough review of system logs and recent changes to identify any additional unauthorized modifications or indicators of compromise.
* Restore any affected system files or configurations from a known good backup to ensure system integrity and functionality.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems are affected.
* Implement enhanced monitoring and alerting for similar unauthorized use of the `defaults` command to improve detection and response capabilities.


## Setup [_setup_1426]

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


## Rule query [_rule_query_5586]

```js
process where host.os.type == "macos" and event.type == "start" and
 process.name == "defaults" and process.args == "write" and process.args : ("LoginHook", "LogoutHook") and
 not process.args :
       (
         "Support/JAMF/ManagementFrameworkScripts/logouthook.sh",
         "Support/JAMF/ManagementFrameworkScripts/loginhook.sh",
         "/Library/Application Support/JAMF/ManagementFrameworkScripts/logouthook.sh",
         "/Library/Application Support/JAMF/ManagementFrameworkScripts/loginhook.sh"
       )
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



