---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-data-exfiltration-activity-to-an-unusual-ip-address.html
---

# Potential Data Exfiltration Activity to an Unusual IP Address [potential-data-exfiltration-activity-to-an-unusual-ip-address]

A machine learning job has detected data exfiltration to a particular geo-location (by IP address). Data transfers to geo-locations that are outside the normal traffic patterns of an organization could indicate exfiltration over command and control channels.

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

## Investigation guide [_investigation_guide_668]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Data Exfiltration Activity to an Unusual IP Address**

Machine learning models analyze network traffic patterns to identify anomalies, such as data transfers to atypical geo-locations. Adversaries exploit command and control channels to exfiltrate data to these unusual IP addresses. This detection rule leverages ML to flag deviations from normal traffic, indicating potential exfiltration activities, thus aiding in early threat identification.

**Possible investigation steps**

* Review the alert details to identify the unusual IP address and geo-location involved in the potential exfiltration activity.
* Cross-reference the identified IP address with threat intelligence databases to determine if it is associated with known malicious activities or threat actors.
* Analyze historical network traffic logs to determine if there have been previous connections to the same IP address or geo-location, and assess the volume and frequency of these connections.
* Investigate the source device or user account associated with the alert to identify any unauthorized access or suspicious behavior leading up to the alert.
* Check for any recent changes in network configurations or security policies that might have inadvertently allowed the data transfer to the unusual IP address.
* Collaborate with the IT team to isolate the affected systems, if necessary, and prevent further data exfiltration while the investigation is ongoing.

**False positive analysis**

* Legitimate business operations involving data transfers to new or infrequent geo-locations may trigger false positives. Users should review these activities and, if deemed non-threatening, add exceptions for these IP addresses.
* Regularly scheduled data backups or transfers to cloud services located in different regions can be misidentified as exfiltration. Users can whitelist these services to prevent unnecessary alerts.
* Remote work scenarios where employees connect from various locations might cause false positives. Implementing a policy to recognize and exclude known employee IP addresses can mitigate this issue.
* Partner or vendor data exchanges that occur outside typical patterns should be evaluated. If these are routine and secure, users can create exceptions for these specific IP addresses to reduce false alerts.

**Response and remediation**

* Isolate the affected systems immediately to prevent further data exfiltration. Disconnect them from the network to stop any ongoing communication with the unusual IP address.
* Conduct a thorough analysis of the affected systems to identify any malicious software or unauthorized access points. Remove any identified threats and patch vulnerabilities.
* Change all credentials and access keys that may have been compromised during the exfiltration activity. Ensure that new credentials follow best practices for security.
* Review and update firewall rules and network access controls to block the identified unusual IP address and similar suspicious IP ranges.
* Monitor network traffic closely for any signs of continued exfiltration attempts or communication with command and control channels. Use enhanced logging and alerting to detect any anomalies.
* Escalate the incident to the organization’s cybersecurity response team and, if necessary, report the breach to relevant authorities or regulatory bodies as per compliance requirements.
* Conduct a post-incident review to identify gaps in the current security posture and implement measures to prevent recurrence, such as improving network segmentation and enhancing threat detection capabilities.


## Setup [_setup_426]

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



