---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-data-exfiltration-activity-to-an-unusual-region.html
---

# Potential Data Exfiltration Activity to an Unusual Region [prebuilt-rule-8-17-4-potential-data-exfiltration-activity-to-an-unusual-region]

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

## Investigation guide [_investigation_guide_4140]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Data Exfiltration Activity to an Unusual Region**

Machine learning models analyze network traffic patterns to identify anomalies, such as data transfers to atypical regions. Adversaries exploit command and control channels to exfiltrate data to these regions, bypassing traditional security measures. This detection rule leverages ML to flag unusual geo-locations, indicating potential exfiltration activities, thus aiding in early threat identification.

**Possible investigation steps**

* Review the geo-location details flagged by the alert to determine if the region is indeed unusual for the organization’s typical network traffic patterns.
* Analyze the network traffic logs associated with the alert to identify the volume and type of data being transferred to the unusual region.
* Cross-reference the IP addresses involved in the data transfer with threat intelligence databases to check for any known malicious activity or associations.
* Investigate the user accounts and devices involved in the data transfer to assess if they have been compromised or are exhibiting other suspicious behaviors.
* Check for any recent changes in network configurations or security policies that might have inadvertently allowed data transfers to atypical regions.
* Collaborate with the organization’s IT and security teams to verify if there are legitimate business reasons for the data transfer to the flagged region.

**False positive analysis**

* Legitimate business operations involving data transfers to new or infrequent regions may trigger false positives. Users should review and whitelist these regions if they are part of regular business activities.
* Scheduled data backups or transfers to cloud services located in atypical regions can be mistaken for exfiltration. Identify and exclude these services from the rule’s scope.
* Remote work scenarios where employees connect from different regions might cause alerts. Maintain an updated list of remote work locations to prevent unnecessary alerts.
* Partner or vendor data exchanges that occur outside usual geographic patterns should be documented and excluded if they are verified as non-threatening.
* Temporary projects or collaborations with international teams may result in unusual data flows. Ensure these are accounted for in the rule’s configuration to avoid false positives.

**Response and remediation**

* Isolate the affected systems immediately to prevent further data exfiltration. Disconnect them from the network to stop ongoing communication with the unusual geo-location.
* Conduct a thorough analysis of the network traffic logs to identify the scope of the exfiltration and determine which data was accessed or transferred.
* Revoke any compromised credentials and enforce a password reset for affected accounts to prevent unauthorized access.
* Implement geo-blocking measures to restrict data transfers to the identified unusual region, ensuring that only approved regions can communicate with the network.
* Review and update firewall and intrusion detection system (IDS) rules to detect and block similar command and control traffic patterns in the future.
* Escalate the incident to the security operations center (SOC) and relevant stakeholders, providing them with detailed findings and actions taken for further investigation and response.
* Conduct a post-incident review to assess the effectiveness of the response and identify any gaps in the security posture, implementing necessary improvements to prevent recurrence.


## Setup [_setup_1010]

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



