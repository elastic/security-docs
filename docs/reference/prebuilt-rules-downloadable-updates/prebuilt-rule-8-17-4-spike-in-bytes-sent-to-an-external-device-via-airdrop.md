---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-spike-in-bytes-sent-to-an-external-device-via-airdrop.html
---

# Spike in Bytes Sent to an External Device via Airdrop [prebuilt-rule-8-17-4-spike-in-bytes-sent-to-an-external-device-via-airdrop]

A machine learning job has detected high bytes of data written to an external device via Airdrop. In a typical operational setting, there is usually a predictable pattern or a certain range of data that is written to external devices. An unusually large amount of data being written is anomalous and can signal illicit data copying or transfer activities.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-2h ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/reference/security/prebuilt-jobs.md](/reference/prebuilt-jobs.md)
* [https://docs.elastic.co/en/integrations/ded](https://docs.elastic.co/en/integrations/ded)
* [https://www.elastic.co/blog/detect-data-exfiltration-activity-with-kibanas-new-integration](https://www.elastic.co/blog/detect-data-exfiltration-activity-with-kibanas-new-integration)

**Tags**:

* Use Case: Data Exfiltration Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Tactic: Exfiltration
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4142]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Spike in Bytes Sent to an External Device via Airdrop**

Airdrop facilitates seamless file sharing between Apple devices, leveraging Bluetooth and Wi-Fi. While convenient, adversaries can exploit it for unauthorized data exfiltration by transferring large volumes of sensitive data. The detection rule employs machine learning to identify anomalies in data transfer patterns, flagging unusual spikes in bytes sent as potential exfiltration attempts, thus aiding in early threat detection.

**Possible investigation steps**

* Review the alert details to identify the specific device and user involved in the data transfer. Check for any known associations with previous incidents or suspicious activities.
* Analyze the volume of data transferred and compare it to typical usage patterns for the device and user. Determine if the spike is significantly higher than usual.
* Investigate the time and context of the data transfer. Correlate with other logs or alerts to identify any concurrent suspicious activities or anomalies.
* Check the destination device’s details to verify if it is a recognized and authorized device within the organization. Investigate any unknown or unauthorized devices.
* Contact the user associated with the alert to verify the legitimacy of the data transfer. Gather information on the nature of the files transferred and the purpose of the transfer.
* Review any recent changes in the user’s access privileges or roles that might explain the increased data transfer activity.

**False positive analysis**

* Regular large file transfers for legitimate business purposes, such as media companies transferring video files, can trigger false positives. Users can create exceptions for specific devices or user accounts known to perform these tasks regularly.
* Software updates or backups that involve transferring large amounts of data to external devices may be misidentified as exfiltration attempts. Users should whitelist these activities by identifying the associated processes or applications.
* Educational institutions or creative teams often share large files for collaborative projects. Establishing a baseline for expected data transfer volumes and excluding these from alerts can reduce false positives.
* Devices used for testing or development purposes might frequently send large data volumes. Users can exclude these devices from monitoring by adding them to an exception list.
* Personal use of Airdrop for transferring large media files, such as photos or videos, can be mistaken for suspicious activity. Users can mitigate this by setting thresholds that account for typical personal use patterns.

**Response and remediation**

* Immediately isolate the affected device from the network to prevent further data exfiltration.
* Verify the identity and permissions of the user associated with the anomalous Airdrop activity to ensure they are authorized to transfer data.
* Conduct a forensic analysis of the device to identify any unauthorized applications or processes that may have facilitated the data transfer.
* Review and revoke any unnecessary permissions or access rights for the user or device involved in the incident.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if the activity is part of a larger threat campaign.
* Implement additional monitoring on the affected device and similar devices to detect any further anomalous Airdrop activities.
* Update security policies and controls to restrict Airdrop usage to only trusted devices and networks, reducing the risk of future unauthorized data transfers.


## Setup [_setup_1012]

**Setup**

The rule requires the Data Exfiltration Detection integration assets to be installed, as well as network and file events collected by integrations such as Elastic Defend and Network Packet Capture (for network events only).

**Data Exfiltration Detection Setup**

The Data Exfiltration Detection integration detects data exfiltration activity by identifying abnormalities in network and file events. Anomalies are detected using Elastic’s Anomaly Detection feature.

**Prerequisite Requirements:**

* Fleet is required for Data Exfiltration Detection.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).
* File events collected by the Elastic Defend integration.
* To install Elastic Defend, refer to the [documentation](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).

**The following steps should be executed to install assets associated with the Data Exfiltration Detection integration:**

* Go to the Kibana homepage. Under Management, click Integrations.
* In the query bar, search for Data Exfiltration Detection and select the integration to see more details about it.
* Follow the instructions under the ***Installation*** section.
* For this rule to work, complete the instructions through ***Add preconfigured anomaly detection jobs***.

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Exfiltration Over Other Network Medium
    * ID: T1011
    * Reference URL: [https://attack.mitre.org/techniques/T1011/](https://attack.mitre.org/techniques/T1011/)



