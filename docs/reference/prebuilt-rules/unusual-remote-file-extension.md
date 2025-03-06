---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-remote-file-extension.html
---

# Unusual Remote File Extension [unusual-remote-file-extension]

An anomaly detection job has detected a remote file transfer with a rare extension, which could indicate potential lateral movement activity on the host.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-90m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

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

## Investigation guide [_investigation_guide_1153]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Remote File Extension**

The detection of unusual remote file extensions leverages machine learning to identify anomalies in file transfers, which may suggest lateral movement by adversaries. Attackers often exploit remote services to transfer files with uncommon extensions, bypassing standard security measures. This rule flags such anomalies, aiding in early detection of potential threats by correlating rare file extensions with known lateral movement tactics.

**Possible investigation steps**

* Review the alert details to identify the specific file extension and the source and destination of the file transfer.
* Check the historical data for the identified file extension to determine if it has been used previously in legitimate activities or if it is indeed rare.
* Investigate the source host to identify any recent changes or suspicious activities, such as new user accounts or unusual login patterns.
* Examine the destination host for any signs of compromise or unauthorized access, focusing on recent file modifications or unexpected processes.
* Correlate the file transfer event with other security alerts or logs to identify potential patterns of lateral movement or exploitation of remote services.
* Consult threat intelligence sources to determine if the rare file extension is associated with known malware or adversary tactics.

**False positive analysis**

* Common internal file transfers with rare extensions may trigger false positives. Review and whitelist known benign file extensions used by internal applications or processes.
* Automated backup or synchronization tools might use uncommon file extensions. Identify these tools and create exceptions for their typical file extensions to prevent unnecessary alerts.
* Development environments often generate files with unique extensions. Collaborate with development teams to understand these patterns and exclude them from detection if they are verified as non-threatening.
* Security tools or scripts that transfer diagnostic or log files with unusual extensions can be mistaken for lateral movement. Document these tools and adjust the rule to ignore their specific file extensions.
* Regularly review and update the list of excluded extensions to ensure it reflects current operational practices and does not inadvertently allow malicious activity.

**Response and remediation**

* Isolate the affected host immediately to prevent further lateral movement and contain the potential threat.
* Review and terminate any suspicious remote sessions or connections identified on the host to cut off unauthorized access.
* Conduct a thorough scan of the affected system for malware or unauthorized software that may have been transferred using the unusual file extension.
* Restore the affected system from a known good backup if any malicious activity or compromise is confirmed.
* Update and patch all software and systems on the affected host to close any vulnerabilities that may have been exploited.
* Monitor network traffic for any further unusual file transfers or connections, focusing on rare file extensions and remote service exploitation patterns.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_727]

**Setup**

The rule requires the Lateral Movement Detection integration assets to be installed, as well as file and Windows RDP process events collected by the Elastic Defend integration.

**Lateral Movement Detection Setup**

The Lateral Movement Detection integration detects lateral movement activity by identifying abnormalities in file and Windows RDP events. Anomalies are detected using Elastic’s Anomaly Detection feature.

**Prerequisite Requirements:**

* Fleet is required for Lateral Movement Detection.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).
* File events collected by the [Elastic Defend](https://docs.elastic.co/en/integrations/endpoint) integration.
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



