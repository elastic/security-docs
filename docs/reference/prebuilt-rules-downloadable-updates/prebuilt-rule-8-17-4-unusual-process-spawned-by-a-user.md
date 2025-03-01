---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-process-spawned-by-a-user.html
---

# Unusual Process Spawned by a User [prebuilt-rule-8-17-4-unusual-process-spawned-by-a-user]

A machine learning job has detected a suspicious Windows process. This process has been classified as malicious in two ways. It was predicted to be malicious by the ProblemChild supervised ML model, and it was found to be suspicious given that its user context is unusual and does not commonly manifest malicious activity,by an unsupervised ML model. Such a process may be an instance of suspicious or malicious activity, possibly involving LOLbins, that may be resistant to detection using conventional search rules.

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

## Investigation guide [_investigation_guide_4293]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Process Spawned by a User**

The detection of unusual processes spawned by users leverages machine learning to identify anomalies in user behavior and process execution. Adversaries often exploit legitimate tools, known as LOLbins, to evade detection. This rule uses both supervised and unsupervised ML models to flag processes that deviate from typical user activity, indicating potential misuse or masquerading tactics.

**Possible investigation steps**

* Review the user context associated with the alert to determine if the user has a history of spawning unusual processes or if this is an isolated incident.
* Examine the specific process flagged by the alert, including its command line arguments, parent process, and any associated network activity, to identify potential indicators of compromise.
* Check for the presence of known LOLbins or other legitimate tools that may have been exploited, as indicated by the alert’s focus on defense evasion tactics.
* Investigate any recent changes in the user’s behavior or system configuration that could explain the anomaly, such as software updates or new application installations.
* Correlate the alert with other security events or logs from the same timeframe to identify any related suspicious activities or patterns.
* Assess the risk score and severity level in the context of the organization’s threat landscape to prioritize the response and determine if further action is needed.

**False positive analysis**

* Legitimate administrative tools may trigger false positives if they are used in atypical contexts. Users should review the context of the process execution and, if deemed safe, add these tools to an exception list to prevent future alerts.
* Scheduled tasks or scripts that run infrequently might be flagged as unusual. Verify the legitimacy of these tasks and consider excluding them if they are part of regular maintenance or updates.
* Software updates or installations can spawn processes that appear anomalous. Confirm the source and purpose of these updates, and if they are routine, create exceptions for these specific processes.
* Developers or IT personnel using command-line tools for legitimate purposes may trigger alerts. Evaluate the necessity of these tools in their workflow and whitelist them if they are consistently used in a non-malicious manner.
* New or infrequently used applications might be flagged due to lack of historical data. Assess the application’s legitimacy and, if appropriate, add it to a list of known safe applications to reduce false positives.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread or communication with potential command and control servers.
* Terminate the suspicious process identified by the alert to halt any ongoing malicious activity.
* Conduct a thorough review of the user’s recent activity and access logs to identify any unauthorized actions or data access.
* Reset the credentials of the affected user account to prevent further unauthorized access, ensuring that strong, unique passwords are used.
* Scan the system for additional indicators of compromise, such as other unusual processes or modifications to system files, and remove any identified threats.
* Restore the system from a known good backup if any critical system files or configurations have been altered.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_1150]

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



