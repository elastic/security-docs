---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-hidden-child-process-of-launchd.html
---

# Suspicious Hidden Child Process of Launchd [suspicious-hidden-child-process-of-launchd]

Identifies the execution of a launchd child process with a hidden file. An adversary can establish persistence by installing a new logon item, launch agent, or daemon that executes upon login.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://objective-see.com/blog/blog_0x61.html](https://objective-see.com/blog/blog_0x61.md)
* [https://www.intezer.com/blog/research/operation-electrorat-attacker-creates-fake-companies-to-drain-your-crypto-wallets/](https://www.intezer.com/blog/research/operation-electrorat-attacker-creates-fake-companies-to-drain-your-crypto-wallets/)
* [https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.md)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_993]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Hidden Child Process of Launchd**

Launchd is a key macOS system process responsible for managing system and user services. Adversaries may exploit it by creating hidden child processes to maintain persistence or evade defenses. The detection rule identifies unusual child processes of launchd, focusing on hidden files, which are often indicative of malicious activity. By monitoring process initiation events, it helps uncover potential threats linked to persistence and defense evasion tactics.

**Possible investigation steps**

* Review the process details to identify the hidden child process, focusing on the process.name field to determine if it matches known malicious patterns or unusual names.
* Examine the process.parent.executable field to confirm that the parent process is indeed /sbin/launchd, ensuring the alert is not a false positive.
* Investigate the file path and attributes of the hidden file associated with the child process to determine its origin and legitimacy.
* Check the user account associated with the process initiation event to assess if it aligns with expected user behavior or if it indicates potential compromise.
* Correlate the event with other recent process initiation events on the same host to identify any patterns or additional suspicious activities.
* Review system logs and other security alerts for the host to gather more context on the potential threat and assess the scope of the activity.

**False positive analysis**

* System updates or legitimate software installations may trigger hidden child processes of launchd. Users can create exceptions for known update processes or trusted software installations to prevent unnecessary alerts.
* Some legitimate applications may use hidden files for configuration or temporary data storage, which could be misidentified as suspicious. Users should identify these applications and whitelist their processes to reduce false positives.
* Development tools or scripts that run as background processes might appear as hidden child processes. Developers can exclude these tools by specifying their process names or paths in the detection rule exceptions.
* Automated backup or synchronization services might create hidden files as part of their normal operation. Users should verify these services and add them to an exclusion list if they are deemed safe.
* Custom scripts or automation tasks scheduled to run at login could be flagged. Users should review these scripts and, if legitimate, configure the rule to ignore these specific processes.

**Response and remediation**

* Isolate the affected macOS system from the network to prevent further spread or communication with potential command and control servers.
* Terminate the suspicious hidden child process of launchd to stop any ongoing malicious activity.
* Conduct a thorough review of all launch agents, daemons, and logon items on the affected system to identify and remove any unauthorized or malicious entries.
* Restore the system from a known good backup if available, ensuring that the backup predates the initial compromise.
* Update the macOS system and all installed applications to the latest versions to patch any vulnerabilities that may have been exploited.
* Monitor the system for any signs of re-infection or further suspicious activity, focusing on process initiation events and hidden files.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be affected.


## Setup [_setup_629]

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


## Rule query [_rule_query_1042]

```js
event.category:process and host.os.type:macos and event.type:(start or process_started) and
 process.name:.* and process.parent.executable:/sbin/launchd
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



