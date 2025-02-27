---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-time-or-day-for-an-rdp-session.html
---

# Unusual Time or Day for an RDP Session [prebuilt-rule-8-17-4-unusual-time-or-day-for-an-rdp-session]

A machine learning job has detected an RDP session started at an usual time or weekday. An RDP session at an unusual time could be followed by other suspicious activities, so catching this is a good first step in detecting a larger attack.

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

## Investigation guide [_investigation_guide_4215]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Time or Day for an RDP Session**

Remote Desktop Protocol (RDP) enables remote access to systems, crucial for IT management but also a target for adversaries seeking unauthorized access. Attackers exploit RDP by initiating sessions at odd hours to avoid detection. The detection rule leverages machine learning to identify atypical RDP session timings, flagging potential lateral movement attempts for further investigation.

**Possible investigation steps**

* Review the timestamp of the RDP session to determine the specific unusual time or day it was initiated, and correlate it with known business hours or scheduled maintenance windows.
* Identify the source and destination IP addresses involved in the RDP session to determine if they are internal or external, and check for any known associations with previous security incidents.
* Examine the user account used to initiate the RDP session, verifying if it is a legitimate account and if the login aligns with the user’s typical behavior or role within the organization.
* Check for any additional suspicious activities or alerts involving the same user account or IP addresses around the time of the unusual RDP session, such as failed login attempts or access to sensitive files.
* Investigate any recent changes or anomalies in the network or system configurations that could have facilitated the unusual RDP session, such as newly opened ports or modified firewall rules.
* Consult logs from other security tools or systems, such as SIEM or endpoint detection and response (EDR) solutions, to gather more context on the RDP session and any related activities.

**False positive analysis**

* Regular maintenance activities by IT staff during off-hours can trigger false positives. Identify and document these activities to create exceptions in the detection rule.
* Scheduled automated tasks or scripts that initiate RDP sessions at unusual times may be misclassified. Review and whitelist these tasks to prevent unnecessary alerts.
* Time zone differences for remote employees accessing systems outside of standard business hours can lead to false positives. Adjust detection parameters to account for these time zone variations.
* Third-party vendors or contractors who require access at non-standard times should be documented and their access patterns reviewed to establish exceptions.
* Emergency access situations where IT staff need to respond to critical incidents outside normal hours should be logged and considered when analyzing alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Terminate the suspicious RDP session to halt any ongoing unauthorized activities.
* Conduct a thorough review of the affected system’s logs and processes to identify any malicious activities or changes made during the session.
* Reset credentials for any accounts accessed during the unusual RDP session to prevent further unauthorized use.
* Apply security patches and updates to the affected system to address any vulnerabilities that may have been exploited.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are compromised.
* Implement enhanced monitoring on the affected system and related network segments to detect any further suspicious activities or attempts at unauthorized access.


## Setup [_setup_1077]

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



