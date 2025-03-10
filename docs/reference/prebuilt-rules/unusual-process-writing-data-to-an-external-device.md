---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-process-writing-data-to-an-external-device.html
---

# Unusual Process Writing Data to an External Device [unusual-process-writing-data-to-an-external-device]

A machine learning job has detected a rare process writing data to an external device. Malicious actors often use benign-looking processes to mask their data exfiltration activities. The discovery of such a process that has no legitimate reason to write data to external devices can indicate exfiltration.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-2h ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)
* [https://docs.elastic.co/en/integrations/ded](https://docs.elastic.co/en/integrations/ded)
* [https://www.elastic.co/blog/detect-data-exfiltration-activity-with-kibanas-new-integration](https://www.elastic.co/blog/detect-data-exfiltration-activity-with-kibanas-new-integration)

**Tags**:

* Use Case: Data Exfiltration Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Tactic: Exfiltration
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1151]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Process Writing Data to an External Device**

In modern environments, processes may write data to external devices for legitimate reasons, such as backups or data transfers. However, adversaries can exploit this by using seemingly harmless processes to exfiltrate sensitive data. The detection rule leverages machine learning to identify rare processes engaging in such activities, flagging potential exfiltration attempts by analyzing deviations from typical behavior patterns.

**Possible investigation steps**

* Review the process name and path to determine if it is commonly associated with legitimate activities or known software.
* Check the user account associated with the process to verify if it has the necessary permissions and if the activity aligns with the user’s typical behavior.
* Analyze the external device’s details, such as its type and connection history, to assess if it is a recognized and authorized device within the organization.
* Investigate the volume and type of data being written to the external device to identify any sensitive or unusual data transfers.
* Correlate the process activity with other security events or logs to identify any concurrent suspicious activities or anomalies.
* Consult with the user or department associated with the process to confirm if the data transfer was authorized and necessary.

**False positive analysis**

* Backup processes may trigger alerts when writing data to external devices. Users should identify and whitelist legitimate backup applications to prevent false positives.
* Data transfer applications used for legitimate business purposes can be flagged. Regularly review and approve these applications to ensure they are not mistakenly identified as threats.
* Software updates or installations that involve writing data to external devices might be detected. Establish a list of known update processes and exclude them from triggering alerts.
* IT maintenance activities, such as system diagnostics or hardware testing, can cause false positives. Document and exclude these routine processes to avoid unnecessary alerts.
* User-initiated file transfers for legitimate reasons, such as moving large datasets for analysis, should be monitored and approved to prevent misclassification.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further data exfiltration and contain the threat.
* Identify and terminate the suspicious process writing data to the external device to stop any ongoing exfiltration activities.
* Conduct a forensic analysis of the affected system to determine the scope of the data exfiltration, including what data was accessed or transferred.
* Review and revoke any compromised credentials or access permissions associated with the affected process to prevent unauthorized access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement additional monitoring on the affected system and similar environments to detect any recurrence of the threat or related suspicious activities.
* Update security policies and controls to prevent similar exfiltration attempts, such as restricting process permissions to write to external devices and enhancing endpoint protection measures.


## Setup [_setup_725]

**Setup**

The rule requires the Data Exfiltration Detection integration assets to be installed, as well as network and file events collected by integrations such as Elastic Defend and Network Packet Capture (for network events only).

**Data Exfiltration Detection Setup**

The Data Exfiltration Detection integration detects data exfiltration activity by identifying abnormalities in network and file events. Anomalies are detected using Elastic’s Anomaly Detection feature.

**Prerequisite Requirements:**

* Fleet is required for Data Exfiltration Detection.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).
* File events collected by the Elastic Defend integration.
* To install Elastic Defend, refer to the [documentation](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).

**The following steps should be executed to install assets associated with the Data Exfiltration Detection integration:**

* Go to the Kibana homepage. Under Management, click Integrations.
* In the query bar, search for Data Exfiltration Detection and select the integration to see more details about it.
* Follow the instructions under the ***Installation*** section.
* For this rule to work, complete the instructions through ***Add preconfigured anomaly detection jobs***.

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Exfiltration Over Physical Medium
    * ID: T1052
    * Reference URL: [https://attack.mitre.org/techniques/T1052/](https://attack.mitre.org/techniques/T1052/)



