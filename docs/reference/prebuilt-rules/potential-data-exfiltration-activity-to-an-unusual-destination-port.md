---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-data-exfiltration-activity-to-an-unusual-destination-port.html
---

# Potential Data Exfiltration Activity to an Unusual Destination Port [potential-data-exfiltration-activity-to-an-unusual-destination-port]

A machine learning job has detected data exfiltration to a particular destination port. Data transfer patterns that are outside the normal traffic patterns of an organization could indicate exfiltration over command and control channels.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-6h ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

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

## Investigation guide [_investigation_guide_667]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Data Exfiltration Activity to an Unusual Destination Port**

Machine learning models analyze network traffic to identify anomalies, such as data transfers to uncommon destination ports, which may suggest exfiltration via command and control channels. Adversaries exploit these channels to stealthily siphon data. This detection rule leverages ML to flag deviations from normal traffic patterns, aiding in early identification of potential threats.

**Possible investigation steps**

* Review the network traffic logs to identify the source IP address associated with the unusual destination port activity. Determine if this IP is known or expected within the organization’s network.
* Analyze the destination port and associated IP address to assess whether it is commonly used for legitimate purposes or if it is known for malicious activity. Cross-reference with threat intelligence databases if necessary.
* Examine the volume and frequency of data transferred to the unusual destination port to identify any patterns or anomalies that deviate from normal behavior.
* Investigate the user or system account associated with the source IP to determine if there are any signs of compromise or unauthorized access.
* Check for any recent changes or updates in the network configuration or security policies that might explain the anomaly.
* Correlate this event with other security alerts or logs to identify any related suspicious activities or patterns that could indicate a broader threat.

**False positive analysis**

* Routine data transfers to external services using uncommon ports may trigger false positives. Identify and document these services to create exceptions in the monitoring system.
* Internal applications that use non-standard ports for legitimate data transfers can be mistaken for exfiltration attempts. Regularly update the list of approved applications and their associated ports to minimize false alerts.
* Scheduled data backups to cloud services or remote servers might use unusual ports. Verify these activities and configure the system to recognize them as non-threatening.
* Development and testing environments often use non-standard ports for various operations. Ensure these environments are well-documented and excluded from exfiltration alerts when appropriate.
* Collaborate with network administrators to maintain an updated inventory of all legitimate network activities and their corresponding ports, reducing the likelihood of false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further data exfiltration and contain the threat.
* Conduct a thorough analysis of the network traffic logs to identify the scope of the exfiltration and determine if other systems are affected.
* Block the identified unusual destination port at the network perimeter to prevent further unauthorized data transfers.
* Review and update firewall and intrusion detection/prevention system (IDS/IPS) rules to block similar exfiltration attempts in the future.
* Notify the incident response team and relevant stakeholders about the potential data breach for further investigation and escalation.
* Perform a comprehensive scan of the affected system for malware or unauthorized software that may have facilitated the exfiltration.
* Implement enhanced monitoring on the affected system and network segment to detect any further suspicious activity.


## Setup [_setup_425]

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



