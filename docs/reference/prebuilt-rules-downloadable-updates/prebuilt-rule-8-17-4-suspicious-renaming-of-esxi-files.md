---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-renaming-of-esxi-files.html
---

# Suspicious Renaming of ESXI Files [prebuilt-rule-8-17-4-suspicious-renaming-of-esxi-files]

Identifies instances where VMware-related files, such as those with extensions like ".vmdk", ".vmx", ".vmxf", ".vmsd", ".vmsn", ".vswp", ".vmss", ".nvram", and ".vmem", are renamed on a Linux system. The rule monitors for the "rename" event action associated with these file types, which could indicate malicious activity.

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

## Investigation guide [_investigation_guide_4356]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Renaming of ESXI Files**

VMware ESXi files are critical for virtual machine operations, storing configurations and states. Adversaries may rename these files to evade detection or disrupt services, a tactic known as masquerading. The detection rule identifies renaming events of specific VMware file types on Linux systems, flagging potential malicious activity by monitoring deviations from expected file extensions.

**Possible investigation steps**

* Review the alert details to identify the specific file that was renamed, including its original and new name, to understand the nature of the change.
* Check the timestamp of the rename event to correlate it with other activities on the system, such as user logins or other file operations, to identify potential patterns or anomalies.
* Investigate the user account or process responsible for the rename action by examining system logs or user activity to determine if the action was authorized or suspicious.
* Analyze the system for any other recent rename events involving VMware-related files to assess if this is an isolated incident or part of a broader pattern.
* Examine the system for signs of compromise or unauthorized access, such as unexpected processes, network connections, or changes in system configurations, to identify potential threats.
* Consult with relevant stakeholders, such as system administrators or security teams, to verify if the rename action was part of a legitimate maintenance or operational task.

**False positive analysis**

* Routine maintenance or administrative tasks may involve renaming VMware ESXi files for organizational purposes. To manage this, identify and exclude specific users or processes that regularly perform these tasks from triggering alerts.
* Automated backup or snapshot processes might rename files temporarily as part of their operation. Review and whitelist these processes to prevent unnecessary alerts.
* Development or testing environments often involve frequent renaming of virtual machine files for configuration testing. Consider excluding these environments from the rule or setting up a separate monitoring profile with adjusted thresholds.
* System updates or patches might include scripts that rename files as part of the update process. Verify and exclude these scripts if they are known and trusted.
* Custom scripts or tools used by IT teams for managing virtual machines may rename files as part of their functionality. Ensure these scripts are documented and excluded from triggering the rule.

**Response and remediation**

* Immediately isolate the affected Linux system from the network to prevent further unauthorized access or potential spread of malicious activity.
* Verify the integrity of the renamed VMware ESXi files by comparing them with known good backups or snapshots, and restore any altered files from a secure backup if necessary.
* Conduct a thorough review of recent system logs and user activity to identify any unauthorized access or actions that may have led to the file renaming.
* Revert any unauthorized changes to system configurations or permissions that may have facilitated the renaming of critical files.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement additional monitoring on the affected system and similar environments to detect any further attempts at file masquerading or other suspicious activities.
* Review and update access controls and permissions for VMware ESXi files to ensure only authorized users have the ability to rename or modify these files.


## Setup [_setup_1204]

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


## Rule query [_rule_query_5348]

```js
file where host.os.type == "linux" and event.action == "rename" and
file.Ext.original.name : ("*.vmdk", "*.vmx", "*.vmxf", "*.vmsd", "*.vmsn", "*.vswp", "*.vmss", "*.nvram", "*.vmem")
and not file.name : ("*.vmdk", "*.vmx", "*.vmxf", "*.vmsd", "*.vmsn", "*.vswp", "*.vmss", "*.nvram", "*.vmem")
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



