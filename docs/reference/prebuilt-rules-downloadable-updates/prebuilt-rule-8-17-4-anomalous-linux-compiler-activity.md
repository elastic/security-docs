---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-anomalous-linux-compiler-activity.html
---

# Anomalous Linux Compiler Activity [prebuilt-rule-8-17-4-anomalous-linux-compiler-activity]

Looks for compiler activity by a user context which does not normally run compilers. This can be the result of ad-hoc software changes or unauthorized software deployment. This can also be due to local privilege elevation via locally run exploits or malware activity.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Tactic: Resource Development
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4644]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Anomalous Linux Compiler Activity**

Compilers transform source code into executable programs, a crucial step in software development. In Linux environments, unexpected compiler use by atypical users may signal unauthorized software changes or privilege escalation attempts. Adversaries exploit this by deploying malicious code or exploits. The detection rule leverages machine learning to identify unusual compiler activity, flagging potential threats by analyzing user behavior patterns and deviations from normal operations.

**Possible investigation steps**

* Review the user account associated with the anomalous compiler activity to determine if the user typically engages in software development or has a history of using compilers.
* Check the specific compiler and version used in the activity to identify if it is a known or legitimate tool within the organization.
* Analyze the source and destination of the compiler activity, including the IP addresses and hostnames, to identify any unusual or unauthorized access patterns.
* Investigate recent changes or deployments on the system where the compiler activity was detected to identify any unauthorized software installations or modifications.
* Examine system logs and audit trails for any signs of privilege escalation attempts or other suspicious activities around the time of the compiler usage.
* Cross-reference the detected activity with known threat intelligence sources to determine if the behavior matches any known attack patterns or indicators of compromise.

**False positive analysis**

* Development environments where multiple users compile code can trigger false positives. Regularly update the list of authorized users who are expected to use compilers to prevent unnecessary alerts.
* Automated build systems or continuous integration pipelines may be flagged. Exclude these systems from monitoring or adjust the rule to recognize their activity as normal.
* Educational or training sessions involving compilers might cause alerts. Temporarily adjust the rule settings or add exceptions for the duration of the training.
* Users compiling open-source software for personal use can be mistaken for threats. Implement a process for users to notify the security team of legitimate compiler use to preemptively adjust monitoring rules.
* System administrators performing maintenance or updates that involve compiling software may trigger alerts. Maintain a log of scheduled maintenance activities and adjust the rule to account for these periods.

**Response and remediation**

* Isolate the affected system from the network to prevent potential lateral movement or further exploitation.
* Terminate any suspicious processes associated with the anomalous compiler activity to halt any ongoing malicious operations.
* Conduct a thorough review of recent user activity and permissions to identify unauthorized access or privilege escalation attempts.
* Remove any unauthorized or malicious software identified during the investigation to prevent further compromise.
* Restore the system from a known good backup if malicious code execution is confirmed, ensuring that the backup is free from compromise.
* Implement stricter access controls and monitoring for compiler usage, ensuring only authorized users can execute compilers.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.


## Setup [_setup_1476]

**Setup**

This rule requires the installation of associated Machine Learning jobs, as well as data coming in from one of the following integrations: - Elastic Defend - Auditd Manager

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

**Auditd Manager Integration Setup**

The Auditd Manager Integration receives audit events from the Linux Audit Framework which is a part of the Linux kernel. Auditd Manager provides a user-friendly interface and automation capabilities for configuring and monitoring system auditing through the auditd daemon. With `auditd_manager`, administrators can easily define audit rules, track system events, and generate comprehensive audit reports, improving overall security and compliance in the system.

**The following steps should be executed in order to add the Elastic Agent System integration "auditd_manager" to your system:**

* Go to the Kibana home page and click “Add integrations”.
* In the query bar, search for “Auditd Manager” and select the integration to see more details about it.
* Click “Add Auditd Manager”.
* Configure the integration name and optionally add a description.
* Review optional and advanced settings accordingly.
* Add the newly installed “auditd manager” to an existing or a new agent policy, and deploy the agent on a Linux system from which auditd log files are desirable.
* Click “Save and Continue”.
* For more details on the integration refer to the [helper guide](https://docs.elastic.co/integrations/auditd_manager).

**Rule Specific Setup Note**

Auditd Manager subscribes to the kernel and receives events as they occur without any additional configuration. However, if more advanced configuration is required to detect specific behavior, audit rules can be added to the integration in either the "audit rules" configuration box or the "auditd rule files" box by specifying a file to read the audit rules from. - For this detection rule no additional audit rules are required.

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Resource Development
    * ID: TA0042
    * Reference URL: [https://attack.mitre.org/tactics/TA0042/](https://attack.mitre.org/tactics/TA0042/)

* Technique:

    * Name: Obtain Capabilities
    * ID: T1588
    * Reference URL: [https://attack.mitre.org/techniques/T1588/](https://attack.mitre.org/techniques/T1588/)

* Sub-technique:

    * Name: Malware
    * ID: T1588.001
    * Reference URL: [https://attack.mitre.org/techniques/T1588/001/](https://attack.mitre.org/techniques/T1588/001/)



