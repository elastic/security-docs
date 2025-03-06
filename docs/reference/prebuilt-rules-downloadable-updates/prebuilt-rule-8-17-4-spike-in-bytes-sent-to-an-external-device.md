---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-spike-in-bytes-sent-to-an-external-device.html
---

# Spike in Bytes Sent to an External Device [prebuilt-rule-8-17-4-spike-in-bytes-sent-to-an-external-device]

A machine learning job has detected high bytes of data written to an external device. In a typical operational setting, there is usually a predictable pattern or a certain range of data that is written to external devices. An unusually large amount of data being written is anomalous and can signal illicit data copying or transfer activities.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-2h ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)
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

## Investigation guide [_investigation_guide_4141]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Spike in Bytes Sent to an External Device**

The detection rule leverages machine learning to identify anomalies in data transfer patterns to external devices, which typically follow predictable trends. Adversaries may exploit this by transferring large volumes of data to external media for exfiltration. The rule detects deviations from normal behavior, flagging potential illicit data transfers for further investigation.

**Possible investigation steps**

* Review the alert details to identify the specific external device involved and the volume of data transferred.
* Correlate the time of the anomaly with user activity logs to determine if the data transfer aligns with any known or authorized user actions.
* Check historical data transfer patterns for the involved device to assess whether the detected spike is truly anomalous or part of a legitimate operational change.
* Investigate the user account associated with the data transfer for any signs of compromise or unusual behavior, such as recent password changes or failed login attempts.
* Examine the content and type of data transferred, if possible, to assess the sensitivity and potential impact of the data exfiltration.
* Cross-reference the device and user activity with other security alerts or incidents to identify any related suspicious activities or patterns.

**False positive analysis**

* Regular backups to external devices can trigger false positives. Users should identify and exclude backup operations from the rule’s scope by specifying known backup software or devices.
* Software updates or installations that involve large data transfers to external media may be misclassified. Users can create exceptions for these activities by defining specific update processes or installation paths.
* Data archiving processes that periodically transfer large volumes of data to external storage can be mistaken for exfiltration. Users should whitelist these scheduled archiving tasks by recognizing the associated patterns or schedules.
* Media content creation or editing, such as video production, often involves significant data transfers. Users can exclude these activities by identifying and excluding the relevant applications or file types.
* Temporary data transfers for legitimate business purposes, like transferring project files to a client, can be flagged. Users should document and exclude these known business processes by specifying the involved devices or file types.

**Response and remediation**

* Immediately isolate the affected device from the network to prevent further data exfiltration.
* Conduct a forensic analysis of the device to identify the source and scope of the data transfer, focusing on the files transferred and any associated processes or applications.
* Review and revoke any unnecessary permissions or access rights that may have facilitated the data transfer to the external device.
* Notify the security operations center (SOC) and relevant stakeholders about the incident for awareness and potential escalation.
* Implement additional monitoring on similar devices and network segments to detect any further anomalous data transfer activities.
* Update and enforce data transfer policies to restrict unauthorized use of external devices, ensuring compliance with organizational security standards.
* Consider deploying endpoint detection and response (EDR) solutions to enhance visibility and control over data movements to external devices.


## Setup [_setup_1011]

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

    * Name: Exfiltration Over Physical Medium
    * ID: T1052
    * Reference URL: [https://attack.mitre.org/techniques/T1052/](https://attack.mitre.org/techniques/T1052/)



