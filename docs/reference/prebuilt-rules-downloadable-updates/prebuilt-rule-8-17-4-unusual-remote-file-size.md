---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-remote-file-size.html
---

# Unusual Remote File Size [prebuilt-rule-8-17-4-unusual-remote-file-size]

A machine learning job has detected an unusually high file size shared by a remote host indicating potential lateral movement activity. One of the primary goals of attackers after gaining access to a network is to locate and exfiltrate valuable information. Instead of multiple small transfers that can raise alarms, attackers might choose to bundle data into a single large file transfer.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-90m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)
* [https://docs.elastic.co/en/integrations/lmd](https://docs.elastic.co/en/integrations/lmd)
* [https://www.elastic.co/blog/detecting-lateral-movement-activity-a-new-kibana-integration](https://www.elastic.co/blog/detecting-lateral-movement-activity-a-new-kibana-integration)
* [https://www.elastic.co/blog/remote-desktop-protocol-connections-elastic-security](https://www.elastic.co/blog/remote-desktop-protocol-connections-elastic-security)

**Tags**:

* Use Case: Lateral Movement Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Tactic: Lateral Movement
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4207]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Remote File Size**

Machine learning models in security environments analyze file transfer patterns to identify anomalies, such as unusually large files shared remotely. Adversaries exploit this by aggregating data into large files to avoid detection during lateral movement. The *Unusual Remote File Size* rule leverages ML to flag these anomalies, aiding in early detection of potential data exfiltration activities.

**Possible investigation steps**

* Review the alert details to identify the specific remote host and file size involved in the anomaly.
* Check the historical file transfer patterns of the identified remote host to determine if this large file size is truly unusual.
* Investigate the contents and purpose of the large file, if accessible, to assess whether it contains sensitive or valuable information.
* Analyze network logs to trace the origin and destination of the file transfer, looking for any unauthorized or suspicious connections.
* Correlate the event with other security alerts or logs to identify any concurrent suspicious activities that might indicate lateral movement or data exfiltration.
* Verify the user account associated with the file transfer to ensure it has not been compromised or misused.

**False positive analysis**

* Large file transfers related to legitimate business operations, such as backups or data migrations, can trigger false positives. Users should identify and whitelist these routine activities to prevent unnecessary alerts.
* Software updates or patches distributed across the network may also appear as unusually large file transfers. Establishing a baseline for expected file sizes during these updates can help in distinguishing them from potential threats.
* Remote file sharing services used for collaboration might generate alerts if large files are shared frequently. Monitoring and excluding these services from the rule can reduce false positives.
* Automated data processing tasks that involve transferring large datasets between systems should be documented and excluded from the rule to avoid false alarms.
* Regularly review and update the list of known safe hosts and services that are permitted to transfer large files, ensuring that only legitimate activities are excluded from detection.

**Response and remediation**

* Isolate the affected host immediately to prevent further lateral movement and potential data exfiltration. Disconnect it from the network to contain the threat.
* Conduct a thorough analysis of the large file transfer to determine its contents and origin. Verify if sensitive data was included and assess the potential impact.
* Review and terminate any unauthorized remote sessions or connections identified during the investigation to prevent further exploitation.
* Reset credentials and review access permissions for the affected host and any associated accounts to mitigate the risk of compromised credentials being used for further attacks.
* Implement network segmentation to limit the ability of attackers to move laterally within the network, reducing the risk of similar incidents in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to ensure comprehensive remediation actions are taken.
* Enhance monitoring and logging for unusual file transfer activities and remote access attempts to improve early detection of similar threats in the future.


## Setup [_setup_1069]

**Setup**

The rule requires the Lateral Movement Detection integration assets to be installed, as well as file and Windows RDP process events collected by the Elastic Defend integration.

**Lateral Movement Detection Setup**

The Lateral Movement Detection integration detects lateral movement activity by identifying abnormalities in file and Windows RDP events. Anomalies are detected using Elastic’s Anomaly Detection feature.

**Prerequisite Requirements:**

* Fleet is required for Lateral Movement Detection.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).
* File events collected by the [Elastic Defend](https://docs.elastic.co/en/integrations/endpoint) integration.
* To install Elastic Defend, refer to the [documentation](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).

**The following steps should be executed to install assets associated with the Lateral Movement Detection integration:**

* Go to the Kibana homepage. Under Management, click Integrations.
* In the query bar, search for Lateral Movement Detection and select the integration to see more details about it.
* Follow the instructions under the ***Installation*** section.
* For this rule to work, complete the instructions through ***Add preconfigured anomaly detection jobs***.

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Exploitation of Remote Services
    * ID: T1210
    * Reference URL: [https://attack.mitre.org/techniques/T1210/](https://attack.mitre.org/techniques/T1210/)



