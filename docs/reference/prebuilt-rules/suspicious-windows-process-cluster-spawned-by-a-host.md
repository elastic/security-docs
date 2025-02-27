---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-windows-process-cluster-spawned-by-a-host.html
---

# Suspicious Windows Process Cluster Spawned by a Host [suspicious-windows-process-cluster-spawned-by-a-host]

A machine learning job combination has detected a set of one or more suspicious Windows processes with unusually high scores for malicious probability. These process(es) have been classified as malicious in several ways. The process(es) were predicted to be malicious by the ProblemChild supervised ML model. If the anomaly contains a cluster of suspicious processes, each process has the same host name, and the aggregate score of the event cluster was calculated to be unusually high by an unsupervised ML model. Such a cluster often contains suspicious or malicious activity, possibly involving LOLbins, that may be resistant to detection using conventional search rules.

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

* Use Case: Living off the Land Attack Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1047]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Windows Process Cluster Spawned by a Host**

The detection leverages machine learning to identify clusters of Windows processes with high malicious probability scores. Adversaries exploit legitimate tools, known as LOLbins, to evade detection. This rule uses both supervised and unsupervised ML models to flag unusual process clusters on a single host, indicating potential masquerading tactics for defense evasion.

**Possible investigation steps**

* Review the host name associated with the suspicious process cluster to determine if it is a critical asset or has a history of similar alerts.
* Examine the specific processes flagged by the ProblemChild supervised ML model to identify any known LOLbins or unusual command-line arguments that may indicate masquerading.
* Check the timeline of the process execution to see if it coincides with any known scheduled tasks or user activity that could explain the anomaly.
* Investigate the parent-child relationship of the processes to identify any unexpected or unauthorized process spawning patterns.
* Correlate the alert with other security events or logs from the same host to identify any additional indicators of compromise or related suspicious activity.
* Assess the network activity associated with the host during the time of the alert to detect any potential data exfiltration or communication with known malicious IP addresses.

**False positive analysis**

* Legitimate administrative tools like PowerShell or Windows Management Instrumentation (WMI) may be flagged as suspicious due to their dual-use nature. Users can create exceptions for these tools when used by trusted administrators or during scheduled maintenance.
* Automated scripts or scheduled tasks that perform routine system checks or updates might trigger alerts. Review these processes and whitelist them if they are verified as part of regular operations.
* Software updates or installations that involve multiple processes spawning in a short time frame can be mistaken for malicious clusters. Ensure that these activities are documented and create exceptions for known update processes.
* Development or testing environments where new or experimental software is frequently executed may generate false positives. Consider excluding these environments from monitoring or adjusting the sensitivity of the rule for these specific hosts.
* Frequent use of remote desktop or remote management tools by IT staff can appear suspicious. Implement user-based exceptions for known IT personnel to reduce unnecessary alerts.

**Response and remediation**

* Isolate the affected host immediately to prevent further spread of potential malicious activity. Disconnect it from the network to contain the threat.
* Terminate the suspicious processes identified by the alert. Use task management tools or scripts to ensure all instances of the processes are stopped.
* Conduct a thorough review of the host’s system logs and process history to identify any additional indicators of compromise or related malicious activity.
* Restore the host from a known good backup if available, ensuring that the backup is free from any signs of compromise.
* Update and patch the host’s operating system and all installed software to close any vulnerabilities that may have been exploited.
* Implement application whitelisting to prevent unauthorized or suspicious processes from executing in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional hosts are affected.


## Setup [_setup_657]

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



