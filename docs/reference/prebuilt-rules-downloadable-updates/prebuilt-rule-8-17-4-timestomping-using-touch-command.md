---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-timestomping-using-touch-command.html
---

# Timestomping using Touch Command [prebuilt-rule-8-17-4-timestomping-using-touch-command]

Timestomping is an anti-forensics technique which is used to modify the timestamps of a file, often to mimic files that are in the same folder.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 33

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* OS: macOS
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3962]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Timestomping using Touch Command**

Timestomping is a technique used by adversaries to alter file timestamps, making malicious files blend with legitimate ones. The *touch* command, prevalent in Linux and macOS, can modify access and modification times. Attackers exploit this to evade detection. The detection rule identifies suspicious *touch* usage by non-root users, focusing on specific arguments and excluding benign processes, thus highlighting potential timestomping activities.

**Possible investigation steps**

* Review the process details to identify the user who executed the *touch* command, focusing on the user.id field to determine if the user is legitimate and authorized to perform such actions.
* Examine the process.args field to understand the specific arguments used with the *touch* command, particularly looking for the use of "-r", "-t", "-a*", or "-m*" which indicate potential timestomping activity.
* Investigate the parent process of the *touch* command by checking the process.parent.name field to determine if it was initiated by a suspicious or unexpected process, excluding known benign processes like "pmlogger_daily", "pmlogger_janitor", and "systemd".
* Cross-reference the file paths and names involved in the *touch* command with known system files and directories to assess if the files are legitimate or potentially malicious.
* Check for any recent alerts or logs related to the same user or process to identify patterns or repeated attempts at timestomping or other suspicious activities.

**False positive analysis**

* Non-root users running legitimate scripts or applications that use the touch command with similar arguments may trigger false positives. To mitigate this, identify and whitelist these specific scripts or applications by adding their paths to the exclusion list.
* Automated system maintenance tasks that involve file timestamp modifications can be mistaken for malicious activity. Review and exclude known maintenance processes by adding them to the exclusion criteria, ensuring they do not match the suspicious argument patterns.
* Development tools or environments that utilize the touch command for file management during build processes might be flagged. Analyze these tools and exclude their typical usage patterns by specifying their paths or parent processes in the exclusion list.
* User-initiated file management activities, such as organizing or backing up files, can inadvertently match the rule’s criteria. Educate users on the implications of using touch with specific arguments and consider excluding common user directories from the rule if they are frequently involved in such activities.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and potential lateral movement by the attacker.
* Conduct a thorough review of the affected system’s file system to identify and document any files with suspicious timestamp modifications, focusing on those altered by non-root users.
* Restore any critical files with altered timestamps from known good backups to ensure data integrity and system reliability.
* Revoke or reset credentials for any non-root users involved in the suspicious *touch* command activity to prevent unauthorized access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring on the affected system and similar environments to detect any further attempts at timestomping or related suspicious activities.
* Review and update access controls and permissions to ensure that only authorized users have the ability to modify file timestamps, reducing the risk of future timestomping attempts.


## Setup [_setup_914]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_4979]

```js
process where event.type == "start" and
 process.name : "touch" and user.id != "0" and
 process.args : ("-r", "-t", "-a*","-m*") and
 not process.args : (
   "/usr/lib/go-*/bin/go", "/usr/lib/dracut/dracut-functions.sh", "/tmp/KSInstallAction.*/m/.patch/*"
) and not process.parent.name in ("pmlogger_daily", "pmlogger_janitor", "systemd")
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

    * Name: Timestomp
    * ID: T1070.006
    * Reference URL: [https://attack.mitre.org/techniques/T1070/006/](https://attack.mitre.org/techniques/T1070/006/)



