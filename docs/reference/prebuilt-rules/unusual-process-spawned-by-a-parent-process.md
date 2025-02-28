---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-process-spawned-by-a-parent-process.html
---

# Unusual Process Spawned by a Parent Process [unusual-process-spawned-by-a-parent-process]

A machine learning job has detected a suspicious Windows process. This process has been classified as malicious in two ways. It was predicted to be malicious by the ProblemChild supervised ML model, and it was found to be an unusual child process name, for the parent process, by an unsupervised ML model. Such a process may be an instance of suspicious or malicious activity, possibly involving LOLbins, that may be resistant to detection using conventional search rules.

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

## Investigation guide [_investigation_guide_1149]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Process Spawned by a Parent Process**

In Windows environments, processes are often spawned by parent processes to perform legitimate tasks. However, adversaries can exploit this by using legitimate tools, known as LOLbins, to execute malicious activities stealthily. The detection rule leverages machine learning to identify anomalies in process creation patterns, flagging processes that deviate from typical behavior, thus uncovering potential threats that evade traditional detection methods.

**Possible investigation steps**

* Review the parent process and child process names to determine if they are known legitimate applications or if they are commonly associated with LOLbins or other malicious activities.
* Check the process creation time and correlate it with any known user activity or scheduled tasks to identify if the process execution aligns with expected behavior.
* Investigate the command line arguments used by the suspicious process to identify any unusual or potentially malicious commands or scripts being executed.
* Analyze the network activity associated with the process to detect any suspicious outbound connections or data exfiltration attempts.
* Examine the file path and hash of the executable to verify its legitimacy and check against known malware databases or threat intelligence sources.
* Review any recent changes to the system, such as software installations or updates, that might explain the unusual process behavior.
* Consult endpoint detection and response (EDR) logs or other security tools to gather additional context and evidence related to the process and its activities.

**False positive analysis**

* Legitimate administrative tools like PowerShell or command prompt may be flagged when used for routine tasks. Users can create exceptions for these tools when executed by known and trusted parent processes.
* Software updates or installations often spawn processes that might appear unusual. Exclude these processes by identifying their typical parent-child relationships during updates.
* Custom scripts or automation tools used within the organization might trigger alerts. Document these scripts and their expected behavior to create exceptions for them.
* Frequent use of remote management tools can lead to false positives. Ensure these tools are whitelisted when used by authorized personnel.
* Regularly review and update the list of exceptions to accommodate changes in legitimate process behaviors over time.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of the potential threat and to contain any malicious activity.
* Terminate the suspicious process identified by the alert to stop any ongoing malicious actions.
* Conduct a thorough analysis of the process and its parent to understand the scope of the compromise and identify any additional malicious activities or files.
* Remove any malicious files or artifacts associated with the process from the system to ensure complete remediation.
* Restore the system from a known good backup if the integrity of the system is compromised beyond repair.
* Update and patch the system to close any vulnerabilities that may have been exploited by the adversary.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_723]

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

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)



