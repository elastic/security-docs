---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-launchdaemon-creation-or-modification-and-immediate-loading.html
---

# LaunchDaemon Creation or Modification and Immediate Loading [prebuilt-rule-8-17-4-launchdaemon-creation-or-modification-and-immediate-loading]

Indicates the creation or modification of a launch daemon, which adversaries may use to repeatedly execute malicious payloads as part of persistence.

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

## Investigation guide [_investigation_guide_4582]

**Triage and analysis**

[TBC: QUOTE]
**Investigating LaunchDaemon Creation or Modification and Immediate Loading**

LaunchDaemons in macOS are system-level services that start at boot and run in the background, often used for legitimate system tasks. However, adversaries can exploit this by creating or modifying LaunchDaemons to ensure persistent execution of malicious payloads. The detection rule identifies such activities by monitoring for new or altered LaunchDaemon files followed by their immediate loading using `launchctl`, indicating potential misuse for persistence.

**Possible investigation steps**

* Review the file path of the newly created or modified LaunchDaemon to determine if it is located in a legitimate system directory such as /System/Library/LaunchDaemons/ or /Library/LaunchDaemons/.
* Examine the contents of the LaunchDaemon file to identify any suspicious or unexpected configurations or scripts that may indicate malicious intent.
* Investigate the process execution details of the launchctl command, including the user account that initiated it, to assess whether it aligns with expected administrative activities.
* Check the timestamp of the LaunchDaemon file creation or modification against known system updates or legitimate software installations to rule out false positives.
* Correlate the event with other security alerts or logs from the same host to identify any additional indicators of compromise or related malicious activities.
* Consult threat intelligence sources to determine if the identified LaunchDaemon or associated scripts are known to be used by specific threat actors or malware campaigns.

**False positive analysis**

* System updates or software installations may create or modify LaunchDaemons as part of legitimate processes. Users can monitor the timing of these activities and correlate them with known update schedules to identify benign occurrences.
* Some third-party applications may use LaunchDaemons for legitimate background tasks. Users should maintain a list of trusted applications and their associated LaunchDaemons to quickly identify and exclude these from alerts.
* Administrative scripts or IT management tools might use launchctl to load LaunchDaemons for system management purposes. Users can create exceptions for known management tools by specifying their process names or paths in the monitoring system.
* Regular system maintenance tasks might involve the creation or modification of LaunchDaemons. Users should document routine maintenance activities and adjust monitoring rules to exclude these known tasks.
* Users can implement a baseline of normal LaunchDaemon activity on their systems to distinguish between expected and unexpected changes, allowing for more accurate identification of false positives.

**Response and remediation**

* Immediately isolate the affected macOS host from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes associated with the newly created or modified LaunchDaemon using the `launchctl` command to unload the daemon.
* Review and remove any unauthorized or suspicious LaunchDaemon files from the directories `/System/Library/LaunchDaemons/` and `/Library/LaunchDaemons/`.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious payloads.
* Restore any altered system files or configurations from a known good backup to ensure system integrity.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for LaunchDaemon activities and `launchctl` usage to detect similar threats in the future.


## Setup [_setup_1414]

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


## Rule query [_rule_query_5574]

```js
sequence by host.id with maxspan=1m
 [file where host.os.type == "macos" and event.type != "deletion" and file.path : ("/System/Library/LaunchDaemons/*", "/Library/LaunchDaemons/*")]
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



