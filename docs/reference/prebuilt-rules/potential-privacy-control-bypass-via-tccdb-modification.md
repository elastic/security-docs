---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-privacy-control-bypass-via-tccdb-modification.html
---

# Potential Privacy Control Bypass via TCCDB Modification [potential-privacy-control-bypass-via-tccdb-modification]

Identifies the use of sqlite3 to directly modify the Transparency, Consent, and Control (TCC) SQLite database. This may indicate an attempt to bypass macOS privacy controls, including access to sensitive resources like the system camera, microphone, address book, and calendar.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://applehelpwriter.com/2016/08/29/discovering-how-dropbox-hacks-your-mac/](https://applehelpwriter.com/2016/08/29/discovering-how-dropbox-hacks-your-mac/)
* [https://github.com/bp88/JSS-Scripts/blob/master/TCC.db%20Modifier.sh](https://github.com/bp88/JSS-Scripts/blob/master/TCC.db%20Modifier.sh)
* [https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_731]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Privacy Control Bypass via TCCDB Modification**

The Transparency, Consent, and Control (TCC) database in macOS manages app permissions for accessing sensitive resources. Adversaries may exploit this by using tools like sqlite3 to alter the TCC database, bypassing privacy controls. The detection rule identifies such attempts by monitoring for suspicious sqlite3 activity targeting the TCC database, excluding legitimate processes, to flag potential privacy control bypasses.

**Possible investigation steps**

* Review the process details to confirm the use of sqlite3, focusing on the process name and arguments to ensure they match the pattern "sqlite*" and include the path "/*/Application Support/com.apple.TCC/TCC.db".
* Investigate the parent process of the sqlite3 activity to determine if it is a known legitimate process or if it appears suspicious, especially if it is not from "/Library/Bitdefender/AVP/product/bin/*".
* Check the timestamp of the sqlite3 activity to correlate it with any other unusual system behavior or alerts that occurred around the same time.
* Examine the user account associated with the process to determine if it has a history of legitimate administrative actions or if it might be compromised.
* Look for any recent changes or anomalies in the TCC database permissions that could indicate unauthorized modifications.
* Assess the system for other signs of compromise, such as unexpected network connections or additional unauthorized processes running, to determine if the sqlite3 activity is part of a larger attack.

**False positive analysis**

* Security software like Bitdefender may legitimately access the TCC database for scanning purposes. To prevent these from being flagged, ensure that the process parent executable path for such software is added to the exclusion list.
* System maintenance tools that perform regular checks or backups might access the TCC database. Identify these tools and add their process paths to the exclusion list to avoid false alerts.
* Developer tools used for testing applications may interact with the TCC database. If these tools are frequently used in your environment, consider excluding their process paths to reduce noise.
* Administrative scripts that automate system configurations might modify the TCC database. Review these scripts and, if deemed safe, exclude their process paths from the detection rule.
* Regular system updates or patches could trigger access to the TCC database. Monitor these events and, if consistent with update schedules, adjust the rule to exclude these specific update processes.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious sqlite3 processes identified in the alert to stop ongoing unauthorized modifications to the TCC database.
* Restore the TCC database from a known good backup to ensure that all privacy settings are reverted to their legitimate state.
* Conduct a thorough review of recent changes to the TCC database to identify any unauthorized access or modifications to sensitive resources.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Implement additional monitoring on the affected system to detect any further attempts to modify the TCC database or other unauthorized activities.
* Review and update access controls and permissions for the TCC database to ensure only authorized processes can make changes, reducing the risk of future bypass attempts.


## Setup [_setup_466]

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


## Rule query [_rule_query_778]

```js
process where host.os.type == "macos" and event.type in ("start", "process_started") and process.name : "sqlite*" and
 process.args : "/*/Application Support/com.apple.TCC/TCC.db" and
 not process.parent.executable : "/Library/Bitdefender/AVP/product/bin/*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



