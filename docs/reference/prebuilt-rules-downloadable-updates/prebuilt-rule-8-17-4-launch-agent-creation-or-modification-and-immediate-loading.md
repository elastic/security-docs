---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-launch-agent-creation-or-modification-and-immediate-loading.html
---

# Launch Agent Creation or Modification and Immediate Loading [prebuilt-rule-8-17-4-launch-agent-creation-or-modification-and-immediate-loading]

An adversary can establish persistence by installing a new launch agent that executes at login by using launchd or launchctl to load a plist into the appropriate directories.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

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
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4580]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Launch Agent Creation or Modification and Immediate Loading**

Launch Agents in macOS are used to execute scripts or applications automatically at user login, providing a mechanism for persistence. Adversaries exploit this by creating or modifying Launch Agents to execute malicious payloads. The detection rule identifies such activities by monitoring file changes in Launch Agent directories and subsequent immediate loading via `launchctl`, indicating potential unauthorized persistence attempts.

**Possible investigation steps**

* Review the file path where the modification or creation of the Launch Agent occurred to determine if it is in a system directory (e.g., /System/Library/LaunchAgents/) or a user directory (e.g., /Users/*/Library/LaunchAgents/). This can help assess the potential impact and scope of the change.
* Examine the contents of the newly created or modified plist file to identify the script or application it is configured to execute. Look for any suspicious or unexpected entries that could indicate malicious activity.
* Check the timestamp of the file modification event to correlate it with any known user activities or other system events that might explain the change.
* Investigate the process execution details of the launchctl command, including the user account under which it was executed and any associated parent processes, to determine if it aligns with legitimate administrative actions or if it appears suspicious.
* Search for any additional related alerts or logs around the same timeframe that might indicate further malicious behavior or corroborate the persistence attempt, such as other process executions or network connections initiated by the suspicious process.

**False positive analysis**

* System or application updates may create or modify Launch Agents as part of their installation or update process. Users can create exceptions for known and trusted applications by whitelisting their specific file paths or process names.
* User-installed applications that require background processes might use Launch Agents for legitimate purposes. Identify these applications and exclude their associated Launch Agent paths from monitoring.
* Administrative scripts or tools used by IT departments for system management might trigger this rule. Coordinate with IT to document these scripts and exclude their activities from detection.
* Development tools or environments that automatically configure Launch Agents for testing purposes can cause false positives. Developers should be aware of these activities and can exclude their specific development directories.
* Backup or synchronization software that uses Launch Agents to schedule tasks may be flagged. Verify these applications and exclude their Launch Agent paths if they are deemed safe.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further malicious activity or lateral movement.
* Terminate any suspicious processes associated with the unauthorized Launch Agent using Activity Monitor or the `kill` command in Terminal.
* Remove the malicious Launch Agent plist file from the affected directories: `/System/Library/LaunchAgents/`, `/Library/LaunchAgents/`, or `/Users/*/Library/LaunchAgents/`.
* Review and restore any system or application settings that may have been altered by the malicious Launch Agent.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or processes.
* Monitor the system for any signs of re-infection or further unauthorized changes to Launch Agents, ensuring that logging and alerting are configured to detect similar activities.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_1412]

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


## Rule query [_rule_query_5572]

```js
sequence by host.id with maxspan=1m
 [file where host.os.type == "macos" and event.type != "deletion" and
  file.path : ("/System/Library/LaunchAgents/*", "/Library/LaunchAgents/*", "/Users/*/Library/LaunchAgents/*")
 ]
 [process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name == "launchctl" and process.args == "load"]
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



