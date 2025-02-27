---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/high-mean-of-rdp-session-duration.html
---

# High Mean of RDP Session Duration [high-mean-of-rdp-session-duration]

A machine learning job has detected unusually high mean of RDP session duration. Long RDP sessions can be used to evade detection mechanisms via session persistence, and might be used to perform tasks such as lateral movement, that might require uninterrupted access to a compromised machine.

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

## Investigation guide [_investigation_guide_409]

**Triage and analysis**

[TBC: QUOTE]
**Investigating High Mean of RDP Session Duration**

Remote Desktop Protocol (RDP) enables remote access to systems, facilitating administrative tasks. However, adversaries exploit prolonged RDP sessions to maintain persistent access, potentially conducting lateral movements undetected. The *High Mean of RDP Session Duration* detection rule leverages machine learning to identify anomalies in session lengths, flagging potential misuse indicative of malicious activity.

**Possible investigation steps**

* Review the specific RDP session details, including the start and end times, to understand the duration and identify any patterns or anomalies in session lengths.
* Correlate the flagged RDP session with user activity logs to determine if the session aligns with expected user behavior or if it deviates from normal patterns.
* Check for any concurrent or subsequent suspicious activities, such as file transfers or command executions, that might indicate lateral movement or data exfiltration.
* Investigate the source and destination IP addresses involved in the RDP session to identify if they are known, trusted, or associated with any previous security incidents.
* Analyze the user account involved in the RDP session for any signs of compromise, such as recent password changes, failed login attempts, or unusual access patterns.
* Review any recent changes in the network or system configurations that might have affected RDP session durations or security settings.

**False positive analysis**

* Extended RDP sessions for legitimate administrative tasks can trigger false positives. To manage this, identify and whitelist IP addresses or user accounts associated with routine administrative activities.
* Scheduled maintenance or software updates often require prolonged RDP sessions. Exclude these activities by setting time-based exceptions during known maintenance windows.
* Remote support sessions from trusted third-party vendors may appear as anomalies. Create exceptions for these vendors by verifying their IP addresses and adding them to an allowlist.
* Training sessions or demonstrations using RDP can result in longer session durations. Document and exclude these events by correlating them with scheduled training times and user accounts involved.
* Automated scripts or processes that maintain RDP sessions for monitoring purposes can be mistaken for threats. Identify these scripts and exclude their associated user accounts or machine names from the detection rule.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious or unauthorized RDP sessions to cut off potential adversary access.
* Conduct a thorough review of user accounts and permissions on the affected system to identify and disable any compromised accounts.
* Apply security patches and updates to the affected system to address any vulnerabilities that may have been exploited.
* Restore the system from a known good backup if any unauthorized changes or malware are detected.
* Monitor network traffic and logs for any signs of further exploitation attempts or related suspicious activity.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to ensure comprehensive remediation.


## Setup [_setup_265]

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



