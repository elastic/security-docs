---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-windows-path-activity.html
---

# Unusual Windows Path Activity [unusual-windows-path-activity]

Identifies processes started from atypical folders in the file system, which might indicate malware execution or persistence mechanisms. In corporate Windows environments, software installation is centrally managed and it is unusual for programs to be executed from user or temporary directories. Processes executed from these locations can denote that a user downloaded software directly from the Internet or a malicious script or macro executed malware.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Tactic: Persistence
* Tactic: Execution
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1164]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Windows Path Activity**

In corporate Windows environments, software is typically managed centrally, making execution from user or temporary directories uncommon. Adversaries exploit this by running malware from these atypical paths, bypassing standard security measures. The *Unusual Windows Path Activity* detection rule leverages machine learning to identify such anomalies, flagging potential persistence or execution tactics used by attackers.

**Possible investigation steps**

* Review the process name and path to determine if it is a known legitimate application or a suspicious executable.
* Check the parent process to understand how the process was initiated and if it correlates with expected user behavior or known software installations.
* Investigate the user account associated with the process execution to verify if the activity aligns with their typical usage patterns or if it appears anomalous.
* Examine the file hash of the executable to see if it matches known malware signatures or if it has been flagged by any threat intelligence sources.
* Look into recent file modifications or creations in the directory from which the process was executed to identify any additional suspicious files or scripts.
* Analyze network connections initiated by the process to detect any unusual or unauthorized external communications.

**False positive analysis**

* Software updates or installations by IT staff can trigger alerts when executed from temporary directories. To manage this, create exceptions for known IT processes or scripts that are regularly used for legitimate software deployment.
* Some legitimate applications may temporarily execute components from user directories during updates or initial setup. Identify these applications and add them to an allowlist to prevent unnecessary alerts.
* Developers or power users might run scripts or applications from non-standard directories for testing purposes. Establish a policy to document and approve such activities, and configure exceptions for these known cases.
* Automated tasks or scripts that are scheduled to run from user directories can be mistaken for malicious activity. Review and document these tasks, then configure the detection rule to exclude them from triggering alerts.
* Security tools or monitoring software might execute diagnostic or remediation scripts from temporary paths. Verify these activities and add them to an exception list to avoid false positives.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of potential malware and unauthorized access.
* Terminate any suspicious processes identified as running from atypical directories to halt malicious activity.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any malicious files.
* Review and restore any modified system processes or configurations to their original state to ensure system integrity.
* Collect and preserve relevant logs and evidence for further analysis and potential escalation to the incident response team.
* Escalate the incident to the security operations center (SOC) or incident response team if the threat persists or if there is evidence of broader compromise.
* Implement application whitelisting to prevent unauthorized execution of software from user or temporary directories in the future.


## Setup [_setup_736]

**Setup**

This rule requires the installation of associated Machine Learning jobs, as well as data coming in from one of the following integrations: - Elastic Defend - Windows

**Anomaly Detection Setup**

Once the rule is enabled, the associated Machine Learning job will start automatically. You can view the Machine Learning job linked under the "Definition" panel of the detection rule. If the job does not start due to an error, the issue must be resolved for the job to commence successfully. For more details on setting up anomaly detection jobs, refer to the [helper guide](docs-content://explore-analyze/machine-learning/anomaly-detection.md).

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration to your system:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, either "Traditional Endpoints" or "Cloud Workloads".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).

**Windows Integration Setup**

The Windows integration allows you to monitor the Windows OS, services, applications, and more.

**The following steps should be executed in order to add the Elastic Agent System integration "windows" to your system:**

* Go to the Kibana home page and click “Add integrations”.
* In the query bar, search for “Windows” and select the integration to see more details about it.
* Click “Add Windows”.
* Configure the integration name and optionally add a description.
* Review optional and advanced settings accordingly.
* Add the newly installed “windows” to an existing or a new agent policy, and deploy the agent on your system from which windows log files are desirable.
* Click “Save and Continue”.
* For more details on the integration refer to the [helper guide](https://docs.elastic.co/integrations/windows).

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Windows Service
    * ID: T1543.003
    * Reference URL: [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: User Execution
    * ID: T1204
    * Reference URL: [https://attack.mitre.org/techniques/T1204/](https://attack.mitre.org/techniques/T1204/)

* Sub-technique:

    * Name: Malicious File
    * ID: T1204.002
    * Reference URL: [https://attack.mitre.org/techniques/T1204/002/](https://attack.mitre.org/techniques/T1204/002/)



