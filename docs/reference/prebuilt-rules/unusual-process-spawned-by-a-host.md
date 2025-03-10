---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-process-spawned-by-a-host.html
---

# Unusual Process Spawned by a Host [unusual-process-spawned-by-a-host]

A machine learning job has detected a suspicious Windows process. This process has been classified as suspicious in two ways. It was predicted to be suspicious by the ProblemChild supervised ML model, and it was found to be an unusual process, on a host that does not commonly manifest malicious activity. Such a process may be an instance of suspicious or malicious activity, possibly involving LOLbins, that may be resistant to detection using conventional search rules.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)
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

## Investigation guide [_investigation_guide_1148]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Process Spawned by a Host**

The detection rule leverages machine learning to identify atypical processes on Windows systems, focusing on those that deviate from normal behavior. Adversaries often exploit legitimate system tools, known as LOLbins, to evade detection. This rule uses the ProblemChild ML model to flag processes that are both statistically unusual and potentially malicious, enhancing detection of stealthy attacks that bypass traditional methods.

**Possible investigation steps**

* Review the process details flagged by the ProblemChild ML model, including the process name, path, and command line arguments, to understand its nature and potential purpose.
* Check the parent process of the flagged process to determine if it was spawned by a legitimate application or a known LOLbin, which might indicate a Living off the Land attack.
* Investigate the host’s historical activity to assess whether this process or similar ones have been executed previously, focusing on any patterns of unusual behavior.
* Correlate the process activity with user logins and network connections to identify any suspicious user behavior or external communications that coincide with the process execution.
* Examine the system’s security logs for any related alerts or anomalies around the time the process was detected, which might provide additional context or evidence of malicious activity.

**False positive analysis**

* Routine administrative tasks may trigger false positives if they involve unusual processes or tools not commonly used on the host. Users can create exceptions for these known tasks to prevent unnecessary alerts.
* Software updates or installations can spawn processes that are atypical but benign. Identifying and excluding these processes during known maintenance windows can reduce false positives.
* Custom scripts or automation tools that mimic LOLbins behavior might be flagged. Users should document and whitelist these scripts if they are verified as safe and necessary for operations.
* Legitimate third-party applications that use system binaries in uncommon ways may be misclassified. Regularly review and update the list of approved applications to ensure they are not mistakenly flagged.
* Temporary spikes in unusual processes due to legitimate business activities, such as end-of-quarter reporting, can be managed by adjusting the detection thresholds or temporarily disabling the rule during these periods.

**Response and remediation**

* Isolate the affected host from the network to prevent further spread or communication with potential command and control servers.
* Terminate the suspicious process identified by the ProblemChild ML model to halt any ongoing malicious activity.
* Conduct a thorough review of the process’s parent and child processes to identify any additional malicious activity or persistence mechanisms.
* Remove any identified LOLbins or unauthorized tools used by the adversary from the system to prevent further exploitation.
* Restore the affected system from a known good backup if any system integrity issues are detected.
* Update endpoint protection and monitoring tools to ensure they can detect similar threats in the future, focusing on the specific techniques used in this incident.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.


## Setup [_setup_722]

**Setup**

The rule requires the Living off the Land (LotL) Attack Detection integration assets to be installed, as well as Windows process events collected by integrations such as Elastic Defend or Winlogbeat.

**LotL Attack Detection Setup**

The LotL Attack Detection integration detects living-off-the-land activity in Windows process events.

**Prerequisite Requirements:**

* Fleet is required for LotL Attack Detection.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).
* Windows process events collected by the [Elastic Defend](https://docs.elastic.co/en/integrations/endpoint) integration or Winlogbeat([/beats/docs/reference/ingestion-tools/beats-winlogbeat/_winlogbeat_overview.md](beats://reference/winlogbeat/_winlogbeat_overview.md)).
* To install Elastic Defend, refer to the [documentation](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).
* To set up and run Winlogbeat, follow [this](beats://reference/winlogbeat/winlogbeat-installation-configuration.md) guide.

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

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)



