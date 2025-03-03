---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-data-exfiltration-activity-to-an-unusual-iso-code.html
---

# Potential Data Exfiltration Activity to an Unusual ISO Code [potential-data-exfiltration-activity-to-an-unusual-iso-code]

A machine learning job has detected data exfiltration to a particular geo-location (by region name). Data transfers to geo-locations that are outside the normal traffic patterns of an organization could indicate exfiltration over command and control channels.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-6h ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

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

## Investigation guide [_investigation_guide_669]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Data Exfiltration Activity to an Unusual ISO Code**

Machine learning models analyze network traffic patterns to identify anomalies, such as data transfers to unexpected geo-locations. Adversaries exploit command and control channels to exfiltrate data to these unusual regions. The detection rule leverages ML to flag deviations from normal traffic, indicating potential exfiltration activities, thus aiding in early threat identification.

**Possible investigation steps**

* Review the alert details to identify the specific unusual ISO code and geo-location involved in the data transfer.
* Analyze network logs to determine the volume and frequency of data transfers to the identified geo-location, comparing it against baseline traffic patterns.
* Investigate the source IP addresses and devices involved in the data transfer to assess whether they are legitimate or potentially compromised.
* Check for any recent changes or anomalies in user behavior or access patterns associated with the source devices or accounts.
* Correlate the alert with other security events or logs, such as authentication logs or endpoint detection alerts, to identify any related suspicious activities.
* Consult threat intelligence sources to determine if the unusual geo-location is associated with known malicious activities or threat actors.

**False positive analysis**

* Legitimate business operations involving data transfers to new or infrequent geo-locations may trigger false positives. Users should review these activities and whitelist known safe destinations.
* Regularly scheduled data backups or transfers to international offices or cloud services can be mistaken for exfiltration. Implement exceptions for these routine operations by updating the model’s baseline.
* Temporary projects or collaborations with partners in unusual regions might cause alerts. Document these activities and adjust the detection parameters to accommodate such temporary changes.
* Changes in business operations, such as expansion into new markets, can alter normal traffic patterns. Update the model to reflect these changes to prevent unnecessary alerts.
* Use historical data to identify patterns of benign traffic to unusual regions and adjust the model’s sensitivity to reduce false positives while maintaining security vigilance.

**Response and remediation**

* Immediately isolate the affected systems from the network to prevent further data exfiltration.
* Conduct a thorough analysis of the network traffic logs to identify the source and destination of the unusual data transfer, focusing on the specific geo-location flagged by the alert.
* Block the identified IP addresses or domains associated with the unusual ISO code in the organization’s firewall and intrusion prevention systems.
* Review and update access controls and permissions to ensure that only authorized personnel have access to sensitive data, reducing the risk of unauthorized data transfers.
* Restore any compromised systems from clean backups, ensuring that all security patches and updates are applied before reconnecting to the network.
* Escalate the incident to the organization’s security operations center (SOC) or incident response team for further investigation and to determine if additional systems or data were affected.
* Implement enhanced monitoring and alerting for similar anomalies in network traffic to improve early detection of potential exfiltration activities in the future.


## Setup [_setup_427]

**Setup**

The rule requires the Data Exfiltration Detection integration assets to be installed, as well as network and file events collected by integrations such as Elastic Defend and Network Packet Capture (for network events only).

**Data Exfiltration Detection Setup**

The Data Exfiltration Detection integration detects data exfiltration activity by identifying abnormalities in network and file events. Anomalies are detected using Elastic’s Anomaly Detection feature.

**Prerequisite Requirements:**

* Fleet is required for Data Exfiltration Detection.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).
* Network events collected by the [Elastic Defend](https://docs.elastic.co/en/integrations/endpoint) or [Network Packet Capture](https://docs.elastic.co/integrations/network_traffic) integration.
* To install Elastic Defend, refer to the [documentation](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).
* To add the Network Packet Capture integration to an Elastic Agent policy, refer to [this](docs-content://reference/ingestion-tools/fleet/add-integration-to-policy.md) guide.

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

    * Name: Exfiltration Over C2 Channel
    * ID: T1041
    * Reference URL: [https://attack.mitre.org/techniques/T1041/](https://attack.mitre.org/techniques/T1041/)



