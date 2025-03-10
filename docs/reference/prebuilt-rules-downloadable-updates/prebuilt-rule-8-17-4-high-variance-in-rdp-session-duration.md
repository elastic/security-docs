---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-high-variance-in-rdp-session-duration.html
---

# High Variance in RDP Session Duration [prebuilt-rule-8-17-4-high-variance-in-rdp-session-duration]

A machine learning job has detected unusually high variance of RDP session duration. Long RDP sessions can be used to evade detection mechanisms via session persistence, and might be used to perform tasks such as lateral movement, that might require uninterrupted access to a compromised machine.

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

## Investigation guide [_investigation_guide_4208]

**Triage and analysis**

[TBC: QUOTE]
**Investigating High Variance in RDP Session Duration**

Remote Desktop Protocol (RDP) enables remote access to systems, facilitating legitimate administrative tasks. However, adversaries exploit prolonged RDP sessions to maintain persistent access, often for lateral movement within networks. The detection rule leverages machine learning to identify anomalies in session duration, flagging potential misuse by highlighting sessions with unusually high variance, which may indicate malicious activity.

**Possible investigation steps**

* Review the specific RDP session details, including the start and end times, to understand the duration and identify any patterns or anomalies in session length.
* Correlate the flagged RDP session with user activity logs to determine if the session aligns with known user behavior or scheduled administrative tasks.
* Investigate the source and destination IP addresses involved in the RDP session to identify any unusual or unauthorized access points.
* Check for any concurrent alerts or logs indicating lateral movement or other suspicious activities originating from the same source or targeting the same destination.
* Analyze the user account associated with the RDP session for any signs of compromise, such as recent password changes, failed login attempts, or unusual access times.
* Review the network traffic during the RDP session for any signs of data exfiltration or communication with known malicious IP addresses.

**False positive analysis**

* Long RDP sessions for legitimate administrative tasks can trigger false positives. To manage this, identify and whitelist IP addresses or user accounts associated with routine administrative activities.
* Scheduled maintenance or updates often require extended RDP sessions. Exclude these sessions by setting time-based exceptions during known maintenance windows.
* Automated scripts or tools that require prolonged RDP access for monitoring or data collection can be mistaken for anomalies. Document and exclude these processes by recognizing their unique session patterns.
* Remote support sessions from trusted third-party vendors may appear as high variance. Establish a list of trusted vendor IPs or accounts to prevent these from being flagged.
* Training or demonstration sessions that involve extended RDP use should be accounted for by creating exceptions for specific user groups or departments involved in such activities.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further lateral movement and potential data exfiltration.
* Terminate the suspicious RDP session to disrupt any ongoing unauthorized activities.
* Conduct a thorough review of the affected system for signs of compromise, including checking for unauthorized user accounts, installed software, and changes to system configurations.
* Reset credentials for any accounts that were accessed during the suspicious RDP session to prevent further unauthorized access.
* Apply security patches and updates to the affected system to address any vulnerabilities that may have been exploited.
* Monitor network traffic and system logs for any signs of continued or related suspicious activity, focusing on RDP connections and lateral movement patterns.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_1070]

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



