---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-machine-learning-detected-a-suspicious-windows-event-with-a-high-malicious-probability-score.html
---

# Machine Learning Detected a Suspicious Windows Event with a High Malicious Probability Score [prebuilt-rule-8-17-4-machine-learning-detected-a-suspicious-windows-event-with-a-high-malicious-probability-score]

A supervised machine learning model (ProblemChild) has identified a suspicious Windows process event with high probability of it being malicious activity. Alternatively, the model’s blocklist identified the event as being malicious.

**Rule type**: eql

**Rule indices**:

* endgame-*
* logs-endpoint.events.process-*
* winlogbeat-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-10m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)
* [https://docs.elastic.co/en/integrations/problemchild](https://docs.elastic.co/en/integrations/problemchild)
* [https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration](https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration)

**Tags**:

* OS: Windows
* Data Source: Elastic Endgame
* Use Case: Living off the Land Attack Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 111

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4294]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Machine Learning Detected a Suspicious Windows Event with a High Malicious Probability Score**

The detection leverages a machine learning model, ProblemChild, to identify potentially malicious Windows processes by analyzing patterns and assigning a high probability score to suspicious activities. Adversaries may exploit legitimate processes to evade detection, often using techniques like masquerading. This rule flags high-risk events by focusing on processes with a high malicious probability score or those identified by a blocklist, excluding known benign activities.

**Possible investigation steps**

* Review the process details flagged by the ProblemChild model, focusing on those with a prediction probability greater than 0.98 or identified by the blocklist.
* Examine the command-line arguments of the suspicious process to identify any unusual or unexpected patterns, excluding those matching known benign patterns like "**C:\\WINDOWS\\temp\\nessus_**.txt*" or "**C:\\WINDOWS\\temp\\nessus_**.tmp*".
* Check the parent process of the flagged event to determine if it is a legitimate process or if it has been potentially compromised.
* Investigate the user account associated with the process to assess if it has been involved in any other suspicious activities or if it has elevated privileges that could be exploited.
* Correlate the event with other security alerts or logs to identify any related activities or patterns that could indicate a broader attack campaign.
* Consult threat intelligence sources to determine if the process or its associated indicators are linked to known malicious activities or threat actors.

**False positive analysis**

* Nessus scan files in the Windows temp directory may trigger false positives due to their temporary nature and frequent legitimate use. Users can mitigate this by adding exceptions for file paths like C:\WINDOWS\temp\nessus_*.txt and C:\WINDOWS\temp\nessus_*.tmp.
* Legitimate software updates or installations might be flagged if they mimic known malicious patterns. Users should review the process details and whitelist trusted software update processes.
* System administration tools that perform actions similar to those used in attacks could be misidentified. Users should verify the legitimacy of these tools and exclude them from the rule if they are part of regular administrative tasks.
* Custom scripts or automation tools that are not widely recognized might be flagged. Users should ensure these scripts are secure and add them to an allowlist if they are part of routine operations.
* Frequent false positives from specific processes can be managed by adjusting the threshold of the machine learning model or refining the blocklist to better distinguish between benign and malicious activities.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of potential malicious activity.
* Terminate the suspicious process identified by the ProblemChild model to halt any ongoing malicious actions.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any additional threats.
* Review and analyze the process execution history and associated files to understand the scope of the compromise and identify any persistence mechanisms.
* Restore any altered or deleted files from backups, ensuring that the backup is clean and free from malware.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for similar processes and activities to detect and respond to future attempts at masquerading or defense evasion.


## Setup [_setup_1151]

**Setup**

The rule requires the Living off the Land (LotL) Attack Detection integration assets to be installed, as well as Windows process events collected by integrations such as Elastic Defend or Winlogbeat.

**LotL Attack Detection Setup**

The LotL Attack Detection integration detects living-off-the-land activity in Windows process events.

**Prerequisite Requirements:**

* Fleet is required for LotL Attack Detection.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).
* Windows process events collected by the [Elastic Defend](https://docs.elastic.co/en/integrations/endpoint) integration or Winlogbeat([/beats/docs/reference/ingestion-tools/beats-winlogbeat/_winlogbeat_overview.md](beats://reference/winlogbeat/_winlogbeat_overview.md)).
* To install Elastic Defend, refer to the [documentation](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).
* To set up and run Winlogbeat, follow [this](beats://reference/winlogbeat/winlogbeat-installation-configuration.md) guide.

**The following steps should be executed to install assets associated with the LotL Attack Detection integration:**

* Go to the Kibana homepage. Under Management, click Integrations.
* In the query bar, search for Living off the Land Attack Detection and select the integration to see more details about it.
* Follow the instructions under the ***Installation*** section.
* For this rule to work, complete the instructions through ***Configure the ingest pipeline***.


## Rule query [_rule_query_5289]

```js
process where ((problemchild.prediction == 1 and problemchild.prediction_probability > 0.98) or
blocklist_label == 1) and not process.args : ("*C:\\WINDOWS\\temp\\nessus_*.txt*", "*C:\\WINDOWS\\temp\\nessus_*.tmp*")
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

    * Name: Masquerade Task or Service
    * ID: T1036.004
    * Reference URL: [https://attack.mitre.org/techniques/T1036/004/](https://attack.mitre.org/techniques/T1036/004/)



