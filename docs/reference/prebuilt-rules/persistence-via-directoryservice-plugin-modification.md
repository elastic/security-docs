---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/persistence-via-directoryservice-plugin-modification.html
---

# Persistence via DirectoryService Plugin Modification [persistence-via-directoryservice-plugin-modification]

Identifies the creation or modification of a DirectoryService PlugIns (dsplug) file. The DirectoryService daemon launches on each system boot and automatically reloads after crash. It scans and executes bundles that are located in the DirectoryServices PlugIns folder and can be abused by adversaries to maintain persistence.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.chichou.me/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://blog.chichou.me/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)

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

## Investigation guide [_investigation_guide_618]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Persistence via DirectoryService Plugin Modification**

DirectoryService PlugIns on macOS are integral for managing directory-based services, automatically executing on system boot. Adversaries exploit this by modifying or creating malicious plugins to ensure persistent access. The detection rule identifies suspicious activity by monitoring non-deletion events involving dsplug files in the PlugIns directory, flagging potential unauthorized modifications indicative of persistence tactics.

**Possible investigation steps**

* Review the alert details to confirm the file path matches /Library/DirectoryServices/PlugIns/*.dsplug, indicating a potential unauthorized modification or creation of a DirectoryService plugin.
* Check the file creation or modification timestamp to determine when the suspicious activity occurred and correlate it with other system events or user activities around that time.
* Investigate the file’s origin by examining the file’s metadata, such as the creator or modifying user, and cross-reference with known user accounts and their typical behavior.
* Analyze the contents of the modified or newly created dsplug file to identify any malicious code or unusual configurations that could indicate adversarial activity.
* Review system logs and other security alerts around the time of the event to identify any related suspicious activities or patterns that could suggest a broader compromise.
* Assess the risk and impact of the modification by determining if the plugin is actively being used for persistence or if it has been executed by the DirectoryService daemon.

**False positive analysis**

* Routine system updates or legitimate software installations may modify dsplug files, triggering alerts. Users can create exceptions for known update processes or trusted software installations to reduce noise.
* Administrative tasks performed by IT personnel, such as configuring directory services, might involve legitimate modifications to dsplug files. Implementing a whitelist for actions performed by verified IT accounts can help minimize false positives.
* Security software or system management tools that interact with directory services might cause benign modifications. Identifying and excluding these tools from monitoring can prevent unnecessary alerts.
* Automated scripts or maintenance tasks that regularly check or update directory service configurations could be flagged. Documenting and excluding these scripts from detection can help maintain focus on genuine threats.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Conduct a thorough review of the identified dsplug file(s) in the /Library/DirectoryServices/PlugIns/ directory to confirm unauthorized modifications or creations. Compare against known good configurations or backups.
* Remove any unauthorized or malicious dsplug files and restore legitimate versions from a trusted backup if available.
* Restart the DirectoryService daemon to ensure it is running only legitimate plugins. This can be done by executing `sudo launchctl stop com.apple.DirectoryServices` followed by `sudo launchctl start com.apple.DirectoryServices`.
* Perform a comprehensive scan of the system using updated security tools to identify any additional malicious files or indicators of compromise.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring on the DirectoryServices PlugIns directory to detect future unauthorized changes promptly, ensuring alerts are configured to notify the security team immediately.


## Setup [_setup_399]

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


## Rule query [_rule_query_660]

```js
event.category:file and host.os.type:macos and not event.type:deletion and
  file.path:/Library/DirectoryServices/PlugIns/*.dsplug
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)



