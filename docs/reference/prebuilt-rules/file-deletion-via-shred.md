---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/file-deletion-via-shred.html
---

# File Deletion via Shred [file-deletion-via-shred]

Malware or other files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_332]

**Triage and analysis**

[TBC: QUOTE]
**Investigating File Deletion via Shred**

The `shred` command in Linux is used to securely delete files by overwriting them, making recovery difficult. Adversaries exploit this to erase traces of malicious activity, hindering forensic analysis. The detection rule identifies suspicious use of `shred` by monitoring its execution with specific arguments, excluding benign processes like `logrotate`, to flag potential defense evasion attempts.

**Possible investigation steps**

* Review the process execution details to confirm the use of the `shred` command with suspicious arguments such as "-u", "--remove", "-z", or "--zero".
* Identify the user account associated with the `shred` process to determine if the activity aligns with expected behavior for that user.
* Investigate the parent process of `shred` to ensure it is not `logrotate` and assess whether the parent process is legitimate or potentially malicious.
* Examine the timeline of events leading up to and following the `shred` execution to identify any related suspicious activities or file modifications.
* Check for any other alerts or logs related to the same host or user to identify patterns or additional indicators of compromise.
* Assess the impact of the file deletion by determining which files were targeted and whether they are critical to system operations or security.

**False positive analysis**

* Logrotate processes may trigger false positives as they use shred for legitimate log file management. Exclude logrotate as a parent process in detection rules to prevent these alerts.
* System maintenance scripts that securely delete temporary files using shred can cause false positives. Identify and whitelist these scripts to reduce unnecessary alerts.
* Backup or cleanup operations that involve shredding old data might be flagged. Review and exclude these operations if they are part of routine system management.
* User-initiated file deletions for privacy or space management can appear suspicious. Educate users on the implications of using shred and consider excluding known user actions if they are frequent and benign.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity or data exfiltration.
* Terminate any active `shred` processes that are not associated with legitimate applications like `logrotate` to halt ongoing file deletion.
* Conduct a thorough review of recent system logs and file access records to identify any additional malicious activities or files that may have been created or modified by the adversary.
* Restore any critical files that were deleted using `shred` from the most recent backup, ensuring the integrity and security of the backup source.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring on the affected system and similar environments to detect any future unauthorized use of `shred` or similar file deletion tools.
* Review and update endpoint security configurations to prevent unauthorized execution of file deletion commands by non-administrative users.


## Setup [_setup_207]

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


## Rule query [_rule_query_351]

```js
process where host.os.type == "linux" and event.type == "start" and process.name == "shred" and process.args in (
  "-u", "--remove", "-z", "--zero"
) and not process.parent.name == "logrotate"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)

* Sub-technique:

    * Name: File Deletion
    * ID: T1070.004
    * Reference URL: [https://attack.mitre.org/techniques/T1070/004/](https://attack.mitre.org/techniques/T1070/004/)



