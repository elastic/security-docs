---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-spike-in-number-of-processes-in-an-rdp-session.html
---

# Spike in Number of Processes in an RDP Session [prebuilt-rule-8-17-4-spike-in-number-of-processes-in-an-rdp-session]

A machine learning job has detected unusually high number of processes started in a single RDP session. Executing a large number of processes remotely on other machines can be an indicator of lateral movement activity.

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

## Investigation guide [_investigation_guide_4213]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Spike in Number of Processes in an RDP Session**

Remote Desktop Protocol (RDP) allows users to connect to other computers over a network, facilitating remote work and administration. However, adversaries can exploit RDP for lateral movement by executing numerous processes on a target machine. The detection rule leverages machine learning to identify anomalies in process activity during RDP sessions, flagging potential exploitation attempts indicative of lateral movement tactics.

**Possible investigation steps**

* Review the specific RDP session details, including the source and destination IP addresses, to identify the involved machines and users.
* Analyze the list of processes that were started during the RDP session to identify any unusual or suspicious processes that are not typically associated with legitimate remote work activities.
* Check the user account associated with the RDP session for any signs of compromise, such as recent password changes or unusual login times.
* Correlate the detected spike in processes with other security events or logs, such as firewall logs or intrusion detection system alerts, to identify any related suspicious activities.
* Investigate the network traffic between the source and destination machines during the RDP session to detect any anomalies or unauthorized data transfers.
* Review historical data for the involved user and machines to determine if similar spikes in process activity have occurred in the past, which could indicate a pattern of malicious behavior.

**False positive analysis**

* High-volume automated tasks or scripts executed during RDP sessions can trigger false positives. Identify and document these tasks, then create exceptions in the detection rule to exclude them from analysis.
* Routine administrative activities, such as software updates or system maintenance, may result in a spike in processes. Regularly review and whitelist these activities to prevent unnecessary alerts.
* Scheduled batch jobs or data processing tasks that run during RDP sessions can be mistaken for lateral movement. Ensure these are logged and excluded from the rule’s scope by setting up appropriate filters.
* Development or testing environments where multiple processes are frequently started as part of normal operations can lead to false positives. Clearly define these environments and adjust the rule to ignore such sessions.

**Response and remediation**

* Isolate the affected machine from the network to prevent further lateral movement and contain the threat.
* Terminate any suspicious or unauthorized processes identified during the RDP session to halt potential malicious activity.
* Conduct a thorough review of the affected machine’s security logs to identify any additional indicators of compromise or related suspicious activity.
* Reset credentials for any accounts that were used during the suspicious RDP session to prevent unauthorized access.
* Apply security patches and updates to the affected machine and any other vulnerable systems to mitigate exploitation of known vulnerabilities.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.
* Enhance monitoring and detection capabilities for RDP sessions by implementing stricter access controls and logging to detect similar anomalies in the future.


## Setup [_setup_1075]

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



