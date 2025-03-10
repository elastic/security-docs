---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-remote-file-directory.html
---

# Unusual Remote File Directory [prebuilt-rule-8-17-4-unusual-remote-file-directory]

An anomaly detection job has detected a remote file transfer on an unusual directory indicating a potential lateral movement activity on the host. Many Security solutions monitor well-known directories for suspicious activities, so attackers might use less common directories to bypass monitoring.

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

## Investigation guide [_investigation_guide_4209]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Remote File Directory**

The *Unusual Remote File Directory* detection leverages machine learning to identify atypical file transfers in directories not commonly monitored, which may indicate lateral movement by adversaries. Attackers exploit these less scrutinized paths to evade detection, often using remote services to transfer malicious payloads. This rule flags such anomalies, aiding in early detection of potential breaches.

**Possible investigation steps**

* Review the alert details to identify the specific unusual directory involved in the file transfer and note any associated file names or types.
* Check the source and destination IP addresses involved in the transfer to determine if they are known or trusted entities within the network.
* Investigate the user account associated with the file transfer to verify if the activity aligns with their typical behavior or role within the organization.
* Examine recent logs or events from the host to identify any other suspicious activities or anomalies that may correlate with the file transfer.
* Cross-reference the detected activity with known threat intelligence sources to determine if the file transfer or directory is associated with any known malicious campaigns or tactics.
* Assess the potential impact of the file transfer by evaluating the sensitivity of the data involved and the criticality of the systems affected.

**False positive analysis**

* Routine administrative tasks may trigger alerts if they involve file transfers to directories not typically monitored. Users can create exceptions for known administrative activities to prevent unnecessary alerts.
* Automated backup processes might be flagged if they store files in uncommon directories. Identifying and excluding these backup operations can reduce false positives.
* Software updates or patches that deploy files to less common directories could be mistaken for suspicious activity. Users should whitelist these update processes to avoid false alerts.
* Development or testing environments often involve file transfers to non-standard directories. Users can configure exceptions for these environments to minimize false positives.
* Legitimate remote services used for file transfers, such as cloud storage synchronization, may be flagged. Users should identify and exclude these trusted services from monitoring.

**Response and remediation**

* Isolate the affected host immediately to prevent further lateral movement and contain the potential threat. Disconnect it from the network to stop any ongoing malicious activity.
* Conduct a thorough analysis of the unusual directory and any files transferred to identify malicious payloads. Use endpoint detection and response (EDR) tools to scan for known malware signatures and behaviors.
* Remove any identified malicious files and artifacts from the affected directory and host. Ensure that all traces of the threat are eradicated to prevent re-infection.
* Reset credentials and review access permissions for the affected host and any associated accounts to mitigate the risk of unauthorized access. Ensure that least privilege principles are enforced.
* Monitor network traffic and logs for any signs of further lateral movement or exploitation attempts. Pay special attention to remote service connections and unusual directory access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional hosts or systems are compromised.
* Update detection mechanisms and rules to enhance monitoring of less common directories and improve the detection of similar threats in the future.


## Setup [_setup_1071]

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



