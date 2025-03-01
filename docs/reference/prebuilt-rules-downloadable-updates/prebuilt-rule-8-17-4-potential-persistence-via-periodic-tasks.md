---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-persistence-via-periodic-tasks.html
---

# Potential Persistence via Periodic Tasks [prebuilt-rule-8-17-4-potential-persistence-via-periodic-tasks]

Identifies the creation or modification of the default configuration for periodic tasks. Adversaries may abuse periodic tasks to execute malicious code or maintain persistence.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://opensource.apple.com/source/crontabs/crontabs-13/private/etc/defaults/periodic.conf.auto.html](https://opensource.apple.com/source/crontabs/crontabs-13/private/etc/defaults/periodic.conf.auto.md)
* [https://www.oreilly.com/library/view/mac-os-x/0596003706/re328.html](https://www.oreilly.com/library/view/mac-os-x/0596003706/re328.md)
* [https://github.com/D00MFist/PersistentJXA/blob/master/PeriodicPersist.js](https://github.com/D00MFist/PersistentJXA/blob/master/PeriodicPersist.js)

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

## Investigation guide [_investigation_guide_4597]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Persistence via Periodic Tasks**

Periodic tasks in macOS are scheduled operations that automate system maintenance and other routine activities. Adversaries may exploit these tasks to execute unauthorized code or maintain persistence by altering task configurations. The detection rule identifies suspicious file activities related to periodic task configurations, excluding deletions, to flag potential misuse. This helps in early detection of persistence mechanisms employed by attackers.

**Possible investigation steps**

* Review the file path specified in the alert to determine which configuration file was created or modified. Focus on paths like /private/etc/periodic/*, /private/etc/defaults/periodic.conf, or /private/etc/periodic.conf.
* Examine the contents of the modified or newly created configuration file to identify any unauthorized or suspicious entries that could indicate malicious activity.
* Check the timestamp of the file modification or creation to correlate with any known suspicious activities or other alerts in the same timeframe.
* Investigate the user account and process responsible for the file modification to determine if it aligns with expected behavior or if it indicates potential compromise.
* Look for any related events in the system logs that might provide additional context or evidence of unauthorized access or persistence attempts.
* Assess the risk and impact of the changes by determining if the modified periodic task could execute malicious code or provide persistence for an attacker.

**False positive analysis**

* Routine system updates or maintenance scripts may trigger alerts when they modify periodic task configurations. Users can create exceptions for known update processes by identifying their specific file paths or process names.
* Administrative tools or scripts used by IT departments for legitimate system management might alter periodic task settings. To mitigate this, users should whitelist these tools by verifying their source and ensuring they are part of authorized IT operations.
* Custom user scripts for personal automation tasks could be flagged if they modify periodic task configurations. Users should document and exclude these scripts by adding them to an exception list, ensuring they are reviewed and approved for legitimate use.
* Security software or monitoring tools that adjust system settings for protection purposes might inadvertently trigger the rule. Users should verify these tools' activities and exclude them if they are confirmed to be part of the security infrastructure.

**Response and remediation**

* Isolate the affected macOS system from the network to prevent potential lateral movement or further execution of unauthorized code.
* Review the identified periodic task configuration files for unauthorized modifications or additions. Restore any altered files to their original state using known good backups.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any malicious code that may have been executed through the periodic tasks.
* Check for any additional persistence mechanisms that may have been established by the adversary, such as other scheduled tasks or startup items, and remove them.
* Monitor the system and network for any signs of continued unauthorized activity or attempts to re-establish persistence.
* Escalate the incident to the security operations team for further investigation and to determine if other systems may be affected.
* Implement enhanced monitoring and alerting for changes to periodic task configurations to quickly detect similar threats in the future.


## Setup [_setup_1429]

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


## Rule query [_rule_query_5589]

```js
event.category:file and host.os.type:macos and not event.type:"deletion" and
 file.path:(/private/etc/periodic/* or /private/etc/defaults/periodic.conf or /private/etc/periodic.conf)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Cron
    * ID: T1053.003
    * Reference URL: [https://attack.mitre.org/techniques/T1053/003/](https://attack.mitre.org/techniques/T1053/003/)



