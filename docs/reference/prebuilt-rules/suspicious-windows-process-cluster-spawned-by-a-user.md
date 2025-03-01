---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-windows-process-cluster-spawned-by-a-user.html
---

# Suspicious Windows Process Cluster Spawned by a User [suspicious-windows-process-cluster-spawned-by-a-user]

A machine learning job combination has detected a set of one or more suspicious Windows processes with unusually high scores for malicious probability. These process(es) have been classified as malicious in several ways. The process(es) were predicted to be malicious by the ProblemChild supervised ML model. If the anomaly contains a cluster of suspicious processes, each process has the same user name, and the aggregate score of the event cluster was calculated to be unusually high by an unsupervised ML model. Such a cluster often contains suspicious or malicious activity, possibly involving LOLbins, that may be resistant to detection using conventional search rules.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/reference/security/prebuilt-jobs.md](/reference/prebuilt-jobs.md)
* [https://docs.elastic.co/en/integrations/problemchild](https://docs.elastic.co/en/integrations/problemchild)
* [https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration](https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Living off the Land Attack Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1049]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Windows Process Cluster Spawned by a User**

The detection leverages machine learning to identify clusters of Windows processes with high malicious probability, often linked to tactics like masquerading. Adversaries exploit legitimate tools (LOLBins) to evade detection. This rule uses both supervised and unsupervised ML models to flag unusual process clusters, focusing on user-associated anomalies to uncover potential threats.

**Possible investigation steps**

* Review the list of processes flagged by the alert to identify any known legitimate applications or tools that might have been misclassified.
* Investigate the user account associated with the suspicious process cluster to determine if there is any history of unusual activity or if the account has been compromised.
* Examine the parent-child relationship of the processes to understand the execution chain and identify any potential masquerading attempts or use of LOLBins.
* Check for any recent changes or updates to the system that might explain the unusual process behavior, such as software installations or updates.
* Correlate the detected processes with any known indicators of compromise (IOCs) or threat intelligence feeds to assess if they are linked to known malicious activity.
* Analyze the network activity associated with the processes to identify any suspicious outbound connections or data exfiltration attempts.

**False positive analysis**

* Legitimate administrative tools like PowerShell or Windows Management Instrumentation (WMI) may trigger false positives due to their frequent use in system management. Users can create exceptions for these tools when used by trusted administrators.
* Software updates or installations often involve processes that mimic suspicious behavior. Exclude these processes by identifying and whitelisting update-related activities from known software vendors.
* Automated scripts or scheduled tasks that perform routine maintenance can be misclassified as malicious. Review and whitelist these tasks if they are part of regular system operations.
* Development environments may spawn multiple processes that resemble malicious clusters. Developers should document and exclude these processes when they are part of legitimate development activities.
* Security software or monitoring tools might generate process clusters that appear suspicious. Ensure these tools are recognized and excluded from analysis to prevent false alerts.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of potential malicious activity.
* Terminate the suspicious processes identified by the alert to halt any ongoing malicious actions.
* Conduct a thorough review of the affected user’s account for any unauthorized access or changes, and reset credentials if necessary.
* Analyze the use of any identified LOLBins to determine if they were used maliciously and restrict their execution through application whitelisting or policy adjustments.
* Collect and preserve relevant logs and forensic data from the affected system for further analysis and to aid in understanding the scope of the incident.
* Escalate the incident to the security operations center (SOC) or incident response team for a deeper investigation and to determine if additional systems are compromised.
* Implement enhanced monitoring and detection rules to identify similar patterns of behavior in the future, focusing on the specific tactics and techniques used in this incident.


## Setup [_setup_659]

**Setup**

The rule requires the Living off the Land (LotL) Attack Detection integration assets to be installed, as well as Windows process events collected by integrations such as Elastic Defend or Winlogbeat.

**LotL Attack Detection Setup**

The LotL Attack Detection integration detects living-off-the-land activity in Windows process events.

**Prerequisite Requirements:**

* Fleet is required for LotL Attack Detection.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).
* Windows process events collected by the [Elastic Defend](https://docs.elastic.co/en/integrations/endpoint) integration or Winlogbeat([/beats/docs/reference/ingestion-tools/beats-winlogbeat/_winlogbeat_overview.md](beats://docs/reference/winlogbeat/_winlogbeat_overview.md)).
* To install Elastic Defend, refer to the [documentation](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).
* To set up and run Winlogbeat, follow [this](beats://docs/reference/winlogbeat/winlogbeat-installation-configuration.md) guide.

**The following steps should be executed to install assets associated with the LotL Attack Detection integration:**

* Go to the Kibana homepage. Under Management, click Integrations.
* In the query bar, search for Living off the Land Attack Detection and select the integration to see more details about it.
* Follow the instructions under the ***Installation*** section.
* For this rule to work, complete the instructions through ***Add preconfigured anomaly detection jobs***.

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)



