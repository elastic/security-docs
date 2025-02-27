---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-renaming-of-esxi-index-html-file.html
---

# Suspicious Renaming of ESXI index.html File [suspicious-renaming-of-esxi-index-html-file]

Identifies instances where the "index.html" file within the "/usr/lib/vmware/*" directory is renamed on a Linux system. The rule monitors for the "rename" event action associated with this specific file and path, which could indicate malicious activity.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.bleepingcomputer.com/news/security/massive-esxiargs-ransomware-attack-targets-vmware-esxi-servers-worldwide/](https://www.bleepingcomputer.com/news/security/massive-esxiargs-ransomware-attack-targets-vmware-esxi-servers-worldwide/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1029]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Renaming of ESXI index.html File**

VMware ESXi hosts use the index.html file within their web interface for management tasks. Adversaries may rename this file to evade detection or to replace it with a malicious version, facilitating unauthorized access or data exfiltration. The detection rule monitors Linux systems for renaming actions targeting this file in the VMware directory, flagging potential defense evasion attempts by correlating file path and event actions.

**Possible investigation steps**

* Review the alert details to confirm the file path and event action, ensuring the "rename" action occurred on the "index.html" file within the "/usr/lib/vmware/*" directory.
* Check the timestamp of the rename event to determine when the activity occurred and correlate it with any other suspicious activities or alerts around the same time.
* Identify the user or process responsible for the rename action by examining the associated user account and process details in the event logs.
* Investigate the system’s recent login history and user activity to identify any unauthorized access or anomalies that could be linked to the rename event.
* Analyze the renamed file and any new files in the directory for signs of tampering or malicious content, using file integrity monitoring tools or antivirus scans.
* Review network logs for any unusual outbound connections from the affected host that could indicate data exfiltration or communication with a command and control server.
* Consider isolating the affected host from the network to prevent further potential malicious activity while the investigation is ongoing.

**False positive analysis**

* Routine maintenance or updates on VMware ESXi hosts may involve renaming the index.html file temporarily. Users can create exceptions for known maintenance windows to prevent unnecessary alerts.
* Automated scripts or backup processes might rename the index.html file as part of their operations. Identify and whitelist these scripts or processes to avoid false positives.
* System administrators may manually rename the index.html file for legitimate customization or troubleshooting purposes. Document and exclude these actions by specific user accounts or during specific time frames.
* Security tools or monitoring solutions might trigger renaming actions as part of their scanning or remediation tasks. Verify and exclude these tools from the rule to reduce false alerts.

**Response and remediation**

* Immediately isolate the affected VMware ESXi host from the network to prevent further unauthorized access or data exfiltration.
* Verify the integrity of the index.html file by comparing it with a known good version from a trusted source to determine if it has been tampered with or replaced.
* Restore the original index.html file from a secure backup if it has been altered or replaced, ensuring that the backup is from a time before the suspicious activity was detected.
* Conduct a thorough review of recent access logs and system changes on the affected host to identify any unauthorized access or modifications that may have occurred.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems may be compromised.
* Implement additional monitoring on the affected host and similar systems to detect any further attempts to rename or modify critical files.
* Review and update access controls and permissions on the VMware ESXi host to ensure that only authorized personnel have the ability to modify critical system files.


## Setup [_setup_648]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a Linux System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, either "Traditional Endpoints" or "Cloud Workloads".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_1080]

```js
file where host.os.type == "linux" and event.action == "rename" and file.name : "index.html" and
file.Ext.original.path : "/usr/lib/vmware/*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Rename System Utilities
    * ID: T1036.003
    * Reference URL: [https://attack.mitre.org/techniques/T1036/003/](https://attack.mitre.org/techniques/T1036/003/)



