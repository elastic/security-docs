---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-microsoft-office-sandbox-evasion.html
---

# Potential Microsoft Office Sandbox Evasion [prebuilt-rule-8-17-4-potential-microsoft-office-sandbox-evasion]

Identifies the creation of a suspicious zip file prepended with special characters. Sandboxed Microsoft Office applications on macOS are allowed to write files that start with special characters, which can be combined with an AutoStart location to achieve sandbox evasion.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://i.blackhat.com/USA-20/Wednesday/us-20-Wardle-Office-Drama-On-macOS.pdf](https://i.blackhat.com/USA-20/Wednesday/us-20-Wardle-Office-Drama-On-macOS.pdf)
* [https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4564]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Microsoft Office Sandbox Evasion**

Microsoft Office applications on macOS operate within a sandbox to limit potential damage from malicious files. However, adversaries can exploit this by creating zip files with special character prefixes, bypassing sandbox restrictions. The detection rule identifies such files, focusing on non-deletion events with specific naming patterns, to flag potential evasion attempts and mitigate risks.

**Possible investigation steps**

* Review the file creation event details to confirm the presence of a zip file with a name starting with special characters, as indicated by the file.name field.
* Examine the file path and location to determine if it aligns with known AutoStart locations, which could indicate an attempt to achieve persistence.
* Investigate the user account associated with the event to assess if the activity is expected or if the account may have been compromised.
* Check for any related events or activities on the same host around the time of the alert, such as other file creations or modifications, to identify potential patterns or additional suspicious behavior.
* Analyze the host’s recent network activity to detect any unusual outbound connections that might suggest data exfiltration or communication with a command and control server.
* Correlate the event with other alerts or logs from the same host or user to build a comprehensive timeline of activities and assess the broader impact or intent.

**False positive analysis**

* Files with special character prefixes created by legitimate applications or processes, such as temporary files generated by Microsoft Office during normal operations, may trigger the rule. Users can create exceptions for known benign applications that frequently generate such files.
* Automated backup or synchronization tools that compress files into zip archives with special character prefixes might be flagged. Identify these tools and exclude their file creation events from the rule.
* Development or testing environments where zip files with special character prefixes are used for legitimate purposes can cause false positives. Implement exclusions for these environments to prevent unnecessary alerts.
* User-generated zip files with special character prefixes for personal organization or naming conventions may be mistakenly identified. Educate users on naming conventions and adjust the rule to exclude specific user directories if needed.

**Response and remediation**

* Isolate the affected macOS system from the network to prevent further potential spread or data exfiltration.
* Quarantine the suspicious zip file to prevent execution and further analysis.
* Conduct a thorough scan of the system using updated antivirus and endpoint detection tools to identify and remove any additional malicious files or processes.
* Review and secure AutoStart locations on the affected system to prevent unauthorized applications from executing at startup.
* Restore any affected files from a known good backup to ensure system integrity and continuity.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if other systems may be affected.
* Update security policies and endpoint protection configurations to block the creation and execution of files with suspicious naming patterns, enhancing future detection and prevention capabilities.


## Setup [_setup_1396]

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


## Rule query [_rule_query_5556]

```js
event.category:file and host.os.type:(macos and macos) and not event.type:deletion and file.name:~$*.zip
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Virtualization/Sandbox Evasion
    * ID: T1497
    * Reference URL: [https://attack.mitre.org/techniques/T1497/](https://attack.mitre.org/techniques/T1497/)



