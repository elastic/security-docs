---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-spike-in-number-of-connections-made-from-a-source-ip.html
---

# Spike in Number of Connections Made from a Source IP [prebuilt-rule-8-17-4-spike-in-number-of-connections-made-from-a-source-ip]

A machine learning job has detected a high count of destination IPs establishing an RDP connection with a single source IP. Once an attacker has gained access to one system, they might attempt to access more in the network in search of valuable assets, data, or further access points.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-12h ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

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

## Investigation guide [_investigation_guide_4211]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Spike in Number of Connections Made from a Source IP**

Remote Desktop Protocol (RDP) is a common tool for remote management, but adversaries exploit it for lateral movement within networks. By establishing numerous connections from a single IP, attackers seek to expand their access. This detection rule leverages machine learning to identify unusual spikes in RDP connections, signaling potential unauthorized access attempts, and aids in early threat identification.

**Possible investigation steps**

* Review the source IP address to determine if it is a known or trusted entity within the network.
* Analyze the list of destination IPs to identify any unusual or unauthorized systems being accessed.
* Check the timestamps of the connections to see if they align with expected activity patterns or occur during unusual hours.
* Investigate the user account associated with the RDP connections to verify if it has been compromised or is being misused.
* Correlate the spike in connections with any recent changes or incidents in the network that might explain the activity.
* Examine network logs and RDP session logs for any signs of suspicious behavior or anomalies during the connection attempts.

**False positive analysis**

* Routine administrative tasks can trigger spikes in RDP connections. Regularly scheduled maintenance or software updates may cause a high number of connections from a single IP. To manage this, identify and whitelist IPs associated with known administrative activities.
* Automated scripts or tools used for network management might establish multiple RDP connections. Review and document these tools, then create exceptions for their IP addresses to prevent false alerts.
* Load balancers or proxy servers can appear as a single source IP making numerous connections. Verify the network architecture and exclude these IPs from the rule to avoid misidentification.
* Security scans or vulnerability assessments conducted by internal teams can result in a spike of connections. Coordinate with security teams to recognize these activities and exclude their IPs from triggering the rule.
* Remote work solutions or VPNs might centralize connections through a single IP, leading to false positives. Identify these IPs and adjust the rule to accommodate legitimate remote access patterns.

**Response and remediation**

* Isolate the affected system immediately to prevent further lateral movement within the network. Disconnect it from the network or place it in a quarantine VLAN.
* Terminate any unauthorized RDP sessions originating from the identified source IP to halt ongoing unauthorized access attempts.
* Conduct a thorough review of the affected system for signs of compromise, including checking for unauthorized user accounts, changes in system configurations, and the presence of malware or suspicious files.
* Reset credentials for any accounts accessed via the compromised system to prevent further unauthorized access using stolen credentials.
* Implement network segmentation to limit RDP access to only necessary systems and users, reducing the attack surface for lateral movement.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the full scope of the breach.
* Update and enhance monitoring rules to detect similar patterns of unusual RDP connection spikes, ensuring early detection of future attempts.


## Setup [_setup_1073]

**Setup**

The rule requires the Lateral Movement Detection integration assets to be installed, as well as file and Windows RDP process events collected by the Elastic Defend integration.

**Lateral Movement Detection Setup**

The Lateral Movement Detection integration detects lateral movement activity by identifying abnormalities in file and Windows RDP events. Anomalies are detected using Elastic’s Anomaly Detection feature.

**Prerequisite Requirements:**

* Fleet is required for Lateral Movement Detection.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).
* Windows RDP process events collected by the [Elastic Defend](https://docs.elastic.co/en/integrations/endpoint) integration.
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



