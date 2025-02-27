---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-linux-process-discovery-activity.html
---

# Unusual Linux Process Discovery Activity [prebuilt-rule-8-17-4-unusual-linux-process-discovery-activity]

Looks for commands related to system process discovery from an unusual user context. This can be due to uncommon troubleshooting activity or due to a compromised account. A compromised account may be used by a threat actor to engage in system process discovery in order to increase their understanding of software applications running on a target host or network. This may be a precursor to selection of a persistence mechanism or a method of privilege elevation.

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
* Tactic: Discovery
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4621]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Linux Process Discovery Activity**

In Linux environments, process discovery commands help users and administrators understand active processes, aiding in system management and troubleshooting. However, adversaries can exploit these commands to map running applications, potentially identifying vulnerabilities for privilege escalation or persistence. The detection rule leverages machine learning to identify atypical usage patterns, flagging potential threats when process discovery occurs from unexpected user contexts, thus helping to preemptively mitigate risks associated with compromised accounts.

**Possible investigation steps**

* Review the user context from which the process discovery command was executed to determine if the user account is expected to perform such actions.
* Check the command history for the user account to identify any other unusual or unauthorized commands executed around the same time.
* Analyze the process discovery command details, including the specific command used and its parameters, to understand the intent and scope of the activity.
* Investigate the source IP address and host from which the command was executed to verify if it aligns with known and authorized devices for the user.
* Examine recent authentication logs for the user account to identify any suspicious login attempts or anomalies in login patterns.
* Correlate the activity with any other alerts or logs that might indicate a broader attack pattern or compromise, such as privilege escalation attempts or lateral movement.

**False positive analysis**

* System administrators performing routine maintenance or troubleshooting may trigger the rule. To manage this, create exceptions for known administrator accounts or specific maintenance windows.
* Automated scripts or monitoring tools that regularly check system processes can be mistaken for unusual activity. Identify these scripts and whitelist their execution context to prevent false alerts.
* New software installations or updates might involve process discovery commands as part of their setup. Monitor installation activities and temporarily adjust the rule sensitivity during these periods.
* Developers or power users who frequently use process discovery commands for legitimate purposes can be excluded by adding their user accounts to an exception list, ensuring their activities do not trigger false positives.
* Training or testing environments where process discovery is part of normal operations should be configured with separate rules or exceptions to avoid unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the threat actor.
* Terminate any suspicious processes identified during the investigation to halt potential malicious activity.
* Change passwords for the compromised account and any other accounts that may have been accessed using the same credentials to prevent further unauthorized access.
* Conduct a thorough review of system logs and user activity to identify any additional signs of compromise or unauthorized access attempts.
* Restore the system from a known good backup if any malicious modifications or persistence mechanisms are detected.
* Implement additional monitoring on the affected system and similar environments to detect any recurrence of unusual process discovery activity.
* Escalate the incident to the security operations team for further analysis and to determine if broader organizational impacts need to be addressed.


## Setup [_setup_1453]

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

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Process Discovery
    * ID: T1057
    * Reference URL: [https://attack.mitre.org/techniques/T1057/](https://attack.mitre.org/techniques/T1057/)



