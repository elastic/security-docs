---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-spike-in-number-of-connections-made-to-a-destination-ip.html
---

# Spike in Number of Connections Made to a Destination IP [prebuilt-rule-8-17-4-spike-in-number-of-connections-made-to-a-destination-ip]

A machine learning job has detected a high count of source IPs establishing an RDP connection with a single destination IP. Attackers might use multiple compromised systems to attack a target to ensure redundancy in case a source IP gets detected and blocked.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-12h ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/reference/security/prebuilt-jobs.md](/reference/prebuilt-jobs.md)
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

## Investigation guide [_investigation_guide_4212]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Spike in Number of Connections Made to a Destination IP**

Remote Desktop Protocol (RDP) is crucial for remote management and troubleshooting in IT environments. However, adversaries exploit RDP by using multiple compromised IPs to overwhelm a target, ensuring persistence even if some IPs are blocked. The detection rule leverages machine learning to identify unusual spikes in RDP connections to a single IP, signaling potential lateral movement attempts by attackers.

**Possible investigation steps**

* Review the list of source IPs that have established RDP connections to the destination IP to identify any known malicious or suspicious IP addresses.
* Check historical data for the destination IP to determine if it has been targeted in previous attacks or if it is a high-value asset within the network.
* Analyze the timing and frequency of the RDP connections to identify any unusual patterns or spikes that could indicate coordinated activity.
* Investigate the user accounts associated with the RDP connections to ensure they are legitimate and have not been compromised.
* Correlate the detected activity with any other security alerts or logs to identify potential lateral movement or further exploitation attempts within the network.

**False positive analysis**

* Routine administrative tasks may trigger false positives if multiple IT staff connect to a server for maintenance. Consider creating exceptions for known administrative IPs.
* Automated scripts or monitoring tools that frequently connect to servers for health checks can cause spikes. Identify and exclude these IPs from the rule.
* Load balancers or proxy servers that aggregate connections from multiple clients might appear as a spike. Exclude these devices from the detection rule.
* Scheduled software updates or deployments that require multiple connections to a server can be mistaken for an attack. Whitelist the IPs involved in these processes.
* Internal network scans or vulnerability assessments conducted by security teams can generate high connection counts. Ensure these activities are recognized and excluded.

**Response and remediation**

* Immediately isolate the affected destination IP from the network to prevent further unauthorized RDP connections and potential lateral movement.
* Conduct a thorough review of the logs and network traffic associated with the destination IP to identify all source IPs involved in the spike and assess the scope of the compromise.
* Block all identified malicious source IPs at the firewall or network perimeter to prevent further connections to the destination IP.
* Reset credentials and enforce multi-factor authentication for accounts that were accessed via RDP to mitigate unauthorized access.
* Perform a security assessment of the affected systems to identify any signs of compromise or unauthorized changes, and restore systems from clean backups if necessary.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems or networks are affected.
* Update and enhance monitoring rules to detect similar patterns of unusual RDP connection spikes in the future, ensuring quick identification and response to potential threats.


## Setup [_setup_1074]

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



