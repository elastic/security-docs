---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-enumeration-of-users-or-groups-via-built-in-commands.html
---

# Enumeration of Users or Groups via Built-in Commands [prebuilt-rule-8-17-4-enumeration-of-users-or-groups-via-built-in-commands]

Identifies the execution of macOS built-in commands related to account or group enumeration. Adversaries may use account and group information to orient themselves before deciding how to act.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Discovery
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4567]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Enumeration of Users or Groups via Built-in Commands**

Built-in macOS commands like `ldapsearch`, `dsmemberutil`, and `dscl` are essential for managing and querying user and group information. Adversaries exploit these to gather insights into system accounts and groups, aiding in lateral movement or privilege escalation. The detection rule identifies suspicious use of these commands, especially when executed from non-standard parent processes, excluding known legitimate applications, to flag potential misuse.

**Possible investigation steps**

* Review the process details to identify the specific command executed, focusing on the process name and arguments, such as "ldapsearch", "dsmemberutil", or "dscl" with specific arguments like "read", "list", or "search".
* Examine the parent process information, including the executable path and name, to determine if the command was launched from a non-standard or suspicious parent process.
* Check the exclusion list of known legitimate applications to ensure the alert was not triggered by a benign process, such as those from QualysCloudAgent, Kaspersky, or ESET.
* Investigate the user account associated with the process execution to determine if it aligns with expected behavior or if it indicates potential compromise or misuse.
* Correlate the event with other logs or alerts to identify any patterns of suspicious activity, such as repeated enumeration attempts or other discovery tactics.
* Assess the system’s recent activity for signs of lateral movement or privilege escalation attempts that may follow the enumeration of users or groups.

**False positive analysis**

* Security and management tools like QualysCloudAgent, Kaspersky Anti-Virus, and ESET Endpoint Security may trigger false positives due to their legitimate use of built-in commands for system monitoring. To mitigate this, add these applications to the exclusion list in the detection rule.
* Development environments such as Xcode might execute these commands during normal operations. If Xcode is frequently triggering alerts, consider excluding its executable path from the rule.
* VPN and network management applications like NordVPN and Zscaler may use these commands for network configuration and user management. Exclude these applications if they are known to be safe and frequently used in your environment.
* Parallels Desktop and similar virtualization software might access user and group information as part of their functionality. If these applications are trusted, add their executable paths to the exclusion list.
* Regular administrative tasks performed by IT personnel using NoMAD or similar tools can also cause false positives. Ensure these tools are excluded if they are part of routine operations.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent potential lateral movement by the adversary.
* Terminate any suspicious processes identified by the detection rule, specifically those involving `ldapsearch`, `dsmemberutil`, or `dscl` commands executed from non-standard parent processes.
* Conduct a thorough review of user and group accounts on the affected system to identify any unauthorized changes or additions, and revert any suspicious modifications.
* Reset passwords for all user accounts on the affected system, prioritizing those with administrative privileges, to mitigate potential unauthorized access.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems have been compromised.
* Implement additional monitoring on the affected system and network to detect any further unauthorized enumeration attempts or related suspicious activities.
* Review and update endpoint security configurations to ensure that legitimate applications are properly whitelisted and that unauthorized applications are blocked from executing enumeration commands.


## Setup [_setup_1399]

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


## Rule query [_rule_query_5559]

```js
process where host.os.type == "macos" and event.type in ("start", "process_started") and
  (
    process.name : ("ldapsearch", "dsmemberutil") or
    (process.name : "dscl" and
      process.args : ("read", "-read", "list", "-list", "ls", "search", "-search") and
      process.args : ("/Active Directory/*", "/Users*", "/Groups*"))
	) and
  ((process.Ext.effective_parent.executable : ("/Volumes/*", "/Applications/*") or process.parent.executable : ("/Volumes/*", "/Applications/*")) or
   (process.Ext.effective_parent.name : ".*" or process.parent.name : ".*")) and
  not process.Ext.effective_parent.executable : ("/Applications/QualysCloudAgent.app/Contents/MacOS/qualys-cloud-agent",
                                                 "/Applications/Kaspersky Anti-Virus For Mac.app/Contents/MacOS/kavd.app/Contents/MacOS/kavd",
                                                 "/Applications/ESET Endpoint Security.app/Contents/MacOS/esets_ctl",
                                                 "/Applications/NordVPN.app/Contents/MacOS/NordVPN",
                                                 "/Applications/Xcode.app/Contents/MacOS/Xcode",
                                                 "/Applications/ESET Endpoint Security.app/Contents/Helpers/Uninstaller.app/Contents/MacOS/Uninstaller",
                                                 "/Applications/Parallels Desktop.app/Contents/MacOS/prl_client_app",
                                                 "/Applications/Zscaler/Zscaler.app/Contents/MacOS/Zscaler",
                                                 "/Applications/com.avast.av.uninstaller.app/Contents/MacOS/com.avast.av.uninstaller",
                                                 "/Applications/NoMAD.app/Contents/MacOS/NoMAD",
                                                 "/Applications/ESET Management Agent.app/Contents/MacOS/ERAAgent")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Permission Groups Discovery
    * ID: T1069
    * Reference URL: [https://attack.mitre.org/techniques/T1069/](https://attack.mitre.org/techniques/T1069/)

* Sub-technique:

    * Name: Local Groups
    * ID: T1069.001
    * Reference URL: [https://attack.mitre.org/techniques/T1069/001/](https://attack.mitre.org/techniques/T1069/001/)

* Technique:

    * Name: Account Discovery
    * ID: T1087
    * Reference URL: [https://attack.mitre.org/techniques/T1087/](https://attack.mitre.org/techniques/T1087/)

* Sub-technique:

    * Name: Local Account
    * ID: T1087.001
    * Reference URL: [https://attack.mitre.org/techniques/T1087/001/](https://attack.mitre.org/techniques/T1087/001/)



