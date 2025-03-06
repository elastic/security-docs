---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-high-mean-of-process-arguments-in-an-rdp-session.html
---

# High Mean of Process Arguments in an RDP Session [prebuilt-rule-8-17-4-high-mean-of-process-arguments-in-an-rdp-session]

A machine learning job has detected unusually high number of process arguments in an RDP session. Executing sophisticated attacks such as lateral movement can involve the use of complex commands, obfuscation mechanisms, redirection and piping, which in turn increases the number of arguments in a command.

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

## Investigation guide [_investigation_guide_4205]

**Triage and analysis**

[TBC: QUOTE]
**Investigating High Mean of Process Arguments in an RDP Session**

Remote Desktop Protocol (RDP) facilitates remote access to systems, often targeted by adversaries for lateral movement. Attackers may exploit RDP by executing complex commands with numerous arguments to obfuscate their actions. The detection rule leverages machine learning to identify anomalies in process arguments, flagging potential misuse indicative of sophisticated attacks.

**Possible investigation steps**

* Review the specific RDP session details, including the source and destination IP addresses, to identify any unusual or unauthorized access patterns.
* Analyze the process arguments flagged by the machine learning model to determine if they include known malicious commands or patterns indicative of obfuscation or redirection.
* Check the user account associated with the RDP session for any signs of compromise, such as recent password changes or login attempts from unusual locations.
* Correlate the alert with other security events or logs, such as firewall logs or intrusion detection system alerts, to identify any related suspicious activities or lateral movement attempts.
* Investigate the historical behavior of the involved systems and users to determine if the high number of process arguments is an anomaly or part of a regular pattern.

**False positive analysis**

* Routine administrative tasks may generate a high number of process arguments, such as batch scripts or automated maintenance operations. Users can create exceptions for known scripts or processes that are regularly executed by trusted administrators.
* Software updates or installations often involve complex commands with multiple arguments. To mitigate false positives, users should whitelist update processes from trusted vendors.
* Monitoring and management tools that perform extensive logging or diagnostics can trigger this rule. Users should identify and exclude these tools if they are verified as non-threatening.
* Custom applications or scripts developed in-house may use numerous arguments for configuration purposes. Users should document and exclude these applications if they are part of normal business operations.
* Scheduled tasks that run during off-hours might appear suspicious due to their complexity. Users can adjust the rule to ignore these tasks if they are part of a regular, approved schedule.

**Response and remediation**

* Isolate the affected system from the network to prevent further lateral movement and potential data exfiltration.
* Terminate any suspicious RDP sessions and associated processes that exhibit high numbers of arguments to halt ongoing malicious activities.
* Conduct a thorough review of the affected system’s event logs and process execution history to identify any unauthorized access or changes made during the RDP session.
* Reset credentials for any accounts that were accessed during the suspicious RDP session to prevent unauthorized access using compromised credentials.
* Apply security patches and updates to the affected system and any other systems within the network to mitigate vulnerabilities that could be exploited for similar attacks.
* Enhance monitoring and logging for RDP sessions across the network to detect and respond to similar anomalies more quickly in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems have been compromised.


## Setup [_setup_1067]

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



