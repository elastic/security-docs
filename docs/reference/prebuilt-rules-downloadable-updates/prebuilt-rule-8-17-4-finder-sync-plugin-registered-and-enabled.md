---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-finder-sync-plugin-registered-and-enabled.html
---

# Finder Sync Plugin Registered and Enabled [prebuilt-rule-8-17-4-finder-sync-plugin-registered-and-enabled]

Finder Sync plugins enable users to extend Finder’s functionality by modifying the user interface. Adversaries may abuse this feature by adding a rogue Finder Plugin to repeatedly execute malicious payloads for persistence.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/specterops/presentations/raw/master/Leo%20Pitt/Hey_Im_Still_in_Here_Modern_macOS_Persistence_SO-CON2020.pdf](https://github.com/specterops/presentations/raw/master/Leo%20Pitt/Hey_Im_Still_in_Here_Modern_macOS_Persistence_SO-CON2020.pdf)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4592]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Finder Sync Plugin Registered and Enabled**

Finder Sync plugins enhance macOS Finder by allowing third-party applications to integrate and modify its interface. While beneficial for legitimate software, adversaries can exploit this feature to maintain persistence by registering malicious plugins. The detection rule identifies suspicious plugin registrations by monitoring the `pluginkit` process, filtering out known safe applications, and flagging unusual activity, thus helping analysts spot potential threats.

**Possible investigation steps**

* Review the process details to confirm the execution of the `pluginkit` process with the specific arguments `-e`, `use`, and `-i`, which indicate the registration of a Finder Sync plugin.
* Cross-reference the plugin identifier found in the process arguments against the list of known safe applications to determine if it is potentially malicious.
* Investigate the parent process of the `pluginkit` execution to identify any unusual or unauthorized parent processes that might suggest malicious activity.
* Check the system for any recent installations or updates of applications that might have introduced the suspicious Finder Sync plugin.
* Analyze the behavior and origin of the executable associated with the suspicious plugin to assess its legitimacy and potential threat level.
* Review system logs and other security alerts around the time of the plugin registration to identify any correlated suspicious activities or anomalies.

**False positive analysis**

* Known safe applications like Google Drive, Boxcryptor, Adobe, Microsoft OneDrive, Insync, and Box are already excluded from triggering false positives. Ensure these applications are up-to-date to maintain their exclusion status.
* If a legitimate application not listed in the exclusions is causing false positives, consider adding its specific Finder Sync plugin identifier to the exclusion list after verifying its safety.
* Monitor the parent process paths of legitimate applications. If a trusted application frequently triggers alerts, add its executable path to the exclusion list to prevent unnecessary alerts.
* Regularly review and update the exclusion list to accommodate new versions or additional legitimate applications that may introduce Finder Sync plugins.
* Educate users on the importance of installing applications from trusted sources to minimize the risk of false positives and ensure that only legitimate plugins are registered.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent potential lateral movement or data exfiltration by the malicious Finder Sync plugin.
* Terminate the suspicious `pluginkit` process to stop the execution of the rogue Finder Sync plugin and prevent further persistence.
* Remove the malicious Finder Sync plugin by unregistering it using the `pluginkit` command with appropriate flags to ensure it cannot be re-enabled.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious payloads or artifacts.
* Review system logs and the Finder Sync plugin registration history to identify any unauthorized changes or additional compromised systems.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if the threat is part of a larger attack campaign.
* Implement enhanced monitoring for `pluginkit` activity and similar persistence mechanisms to detect and respond to future attempts promptly.


## Setup [_setup_1424]

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


## Rule query [_rule_query_5584]

```js
process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name : "pluginkit" and
  process.args : "-e" and process.args : "use" and process.args : "-i" and
  not process.args :
  (
    "com.google.GoogleDrive.FinderSyncAPIExtension",
    "com.google.drivefs.findersync",
    "com.boxcryptor.osx.Rednif",
    "com.adobe.accmac.ACCFinderSync",
    "com.microsoft.OneDrive.FinderSync",
    "com.insynchq.Insync.Insync-Finder-Integration",
    "com.box.desktop.findersyncext"
  ) and
  not process.parent.executable : ("/Library/Application Support/IDriveforMac/IDriveHelperTools/FinderPluginApp.app/Contents/MacOS/FinderPluginApp",
                                   "/Applications/Google Drive.app/Contents/MacOS/Google Drive") and
  not process.Ext.effective_parent.executable : ("/Applications/Google Drive.app/Contents/MacOS/Google Drive",
                                                 "/usr/local/jamf/bin/jamf",
                                                 "/Applications/Nextcloud.app/Contents/MacOS/Nextcloud",
                                                 "/Library/Application Support/Checkpoint/Endpoint Security/AMFinderExtensions.app/Contents/MacOS/AMFinderExtensions",
                                                 "/Applications/pCloud Drive.app/Contents/MacOS/pCloud Drive")
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



