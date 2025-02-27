---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-emond-rules-creation-or-modification.html
---

# Emond Rules Creation or Modification [prebuilt-rule-8-17-4-emond-rules-creation-or-modification]

Identifies the creation or modification of the Event Monitor Daemon (emond) rules. Adversaries may abuse this service by writing a rule to execute commands when a defined event occurs, such as system start up or user authentication.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.xorrior.com/emond-persistence/](https://www.xorrior.com/emond-persistence/)
* [https://www.sentinelone.com/blog/how-malware-persists-on-macos/](https://www.sentinelone.com/blog/how-malware-persists-on-macos/)

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

## Investigation guide [_investigation_guide_4588]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Emond Rules Creation or Modification**

The Event Monitor Daemon (emond) on macOS is a service that executes commands based on specific system events. Adversaries can exploit this by crafting rules to trigger malicious actions during events like startup or login. The detection rule monitors for new or altered emond rule files, signaling potential unauthorized modifications that could indicate persistence tactics.

**Possible investigation steps**

* Review the file path of the modified or newly created emond rule to determine if it matches known legitimate configurations or if it appears suspicious, focusing on paths like "/private/etc/emond.d/rules/**.plist" and "/private/var/db/emondClients/**".
* Check the timestamp of the file creation or modification to correlate with any known user activity or scheduled tasks that could explain the change.
* Analyze the contents of the modified or newly created plist file to identify any commands or scripts that are set to execute, looking for signs of malicious intent or unauthorized actions.
* Investigate the user account associated with the file modification event to determine if the activity aligns with their typical behavior or if it suggests potential compromise.
* Cross-reference the event with other security alerts or logs from the same timeframe to identify any related suspicious activities or patterns that could indicate a broader attack.

**False positive analysis**

* System or application updates may modify emond rule files as part of legitimate maintenance activities. Users can create exceptions for known update processes by identifying the associated process names or hashes and excluding them from alerts.
* Administrative tasks performed by IT personnel, such as configuring new system policies or settings, might involve legitimate changes to emond rules. To handle these, maintain a list of authorized personnel and their activities, and exclude these from triggering alerts.
* Security software or management tools that automate system configurations could also modify emond rules. Identify these tools and their expected behaviors, and configure exceptions based on their typical file paths or process identifiers.
* Scheduled maintenance scripts that interact with emond rules for system health checks or optimizations should be documented. Exclude these scripts by verifying their signatures or paths to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent potential lateral movement or further execution of malicious rules.
* Review and back up the current emond rule files located in the specified directories to understand the scope of modifications and preserve evidence for further analysis.
* Remove or revert any unauthorized or suspicious emond rule files to their original state to stop any malicious actions triggered by these rules.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection tools to identify and remove any additional malware or persistence mechanisms.
* Restore the system from a known good backup if the integrity of the system is in question and unauthorized changes cannot be fully reversed.
* Escalate the incident to the security operations team for further investigation and to determine if other systems may be affected by similar unauthorized emond rule modifications.
* Implement enhanced monitoring and alerting for changes to emond rule files to quickly detect and respond to future unauthorized modifications.


## Setup [_setup_1420]

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


## Rule query [_rule_query_5580]

```js
file where host.os.type == "macos" and event.type != "deletion" and
 file.path : ("/private/etc/emond.d/rules/*.plist", "/etc/emon.d/rules/*.plist", "/private/var/db/emondClients/*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Emond
    * ID: T1546.014
    * Reference URL: [https://attack.mitre.org/techniques/T1546/014/](https://attack.mitre.org/techniques/T1546/014/)



