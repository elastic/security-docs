---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/spike-in-remote-file-transfers.html
---

# Spike in Remote File Transfers [spike-in-remote-file-transfers]

A machine learning job has detected an abnormal volume of remote files shared on the host indicating potential lateral movement activity. One of the primary goals of attackers after gaining access to a network is to locate and exfiltrate valuable information. Attackers might perform multiple small transfers to match normal egress activity in the network, to evade detection.

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

## Investigation guide [_investigation_guide_946]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Spike in Remote File Transfers**

Remote file transfer technologies facilitate data sharing across networks, essential for collaboration and operations. However, adversaries exploit these to move laterally within a network, often transferring data stealthily to avoid detection. The *Spike in Remote File Transfers* detection rule leverages machine learning to identify unusual transfer volumes, signaling potential malicious activity by comparing against established network baselines.

**Possible investigation steps**

* Review the alert details to identify the specific host and time frame associated with the abnormal file transfer activity.
* Analyze network logs and remote file transfer logs to determine the source and destination of the transfers, focusing on any unusual or unauthorized endpoints.
* Cross-reference the identified host with known assets and user accounts to verify if the activity aligns with expected behavior or if it involves unauthorized access.
* Investigate any associated user accounts for signs of compromise, such as unusual login times or locations, by reviewing authentication logs.
* Check for any recent changes or anomalies in the network baseline that could explain the spike in file transfers, such as new software deployments or legitimate large data migrations.
* Correlate the detected activity with other security alerts or incidents to identify potential patterns or coordinated attacks within the network.

**False positive analysis**

* Regularly scheduled data backups or synchronization tasks can trigger false positives. Identify these tasks and create exceptions to prevent them from being flagged.
* Automated software updates or patch management systems may cause spikes in file transfers. Exclude these systems from the rule to reduce false alerts.
* Internal data sharing between departments for legitimate business purposes might be misidentified. Establish a baseline for these activities and adjust the detection thresholds accordingly.
* High-volume data transfers during specific business operations, such as end-of-month reporting, can be mistaken for malicious activity. Temporarily adjust the rule settings during these periods to accommodate expected increases in transfer volumes.
* Frequent file transfers from trusted external partners or vendors should be monitored and, if consistently benign, added to an allowlist to minimize unnecessary alerts.

**Response and remediation**

* Isolate the affected host immediately to prevent further lateral movement and potential data exfiltration. Disconnect it from the network to contain the threat.
* Conduct a thorough analysis of the transferred files to determine if sensitive data was involved and assess the potential impact of the data exposure.
* Review and terminate any unauthorized remote access sessions or services on the affected host to prevent further exploitation.
* Reset credentials for any accounts that were used or potentially compromised during the incident to prevent unauthorized access.
* Apply security patches and updates to the affected systems to address any vulnerabilities that may have been exploited by the attackers.
* Monitor network traffic for any additional unusual remote file transfer activities, using enhanced logging and alerting to detect similar threats in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to ensure comprehensive remediation efforts are undertaken.


## Setup [_setup_600]

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



