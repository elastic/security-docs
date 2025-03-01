---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-linux-system-information-discovery-activity.html
---

# Unusual Linux System Information Discovery Activity [prebuilt-rule-8-17-4-unusual-linux-system-information-discovery-activity]

Looks for commands related to system information discovery from an unusual user context. This can be due to uncommon troubleshooting activity or due to a compromised account. A compromised account may be used to engage in system information discovery in order to gather detailed information about system configuration and software versions. This may be a precursor to selection of a persistence mechanism or a method of privilege elevation.

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

## Investigation guide [_investigation_guide_4618]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Linux System Information Discovery Activity**

In Linux environments, system information discovery involves commands that reveal details about system configuration and software versions. While typically used for legitimate troubleshooting, adversaries exploit this to gather intelligence for further attacks, such as privilege escalation. The detection rule leverages machine learning to identify atypical usage patterns, flagging potential misuse by compromised accounts.

**Possible investigation steps**

* Review the alert details to identify the specific user account and the command executed that triggered the alert. Focus on any unusual or unexpected user context.
* Check the user’s activity history to determine if this type of command execution is typical for the user or if it deviates from their normal behavior.
* Investigate the source IP address and hostname associated with the alert to verify if they are consistent with the user’s usual access patterns or if they indicate potential unauthorized access.
* Examine system logs for any additional suspicious activities or anomalies around the time of the alert, such as failed login attempts or other unusual commands executed.
* Assess whether the command executed could be part of a legitimate troubleshooting process or if it aligns with known tactics for privilege escalation or persistence.
* If the account is suspected to be compromised, consider resetting the user’s credentials and conducting a broader investigation into potential lateral movement or data exfiltration activities.

**False positive analysis**

* Routine administrative tasks by system administrators may trigger alerts. To manage this, create exceptions for known admin accounts performing regular maintenance.
* Automated scripts for system monitoring or inventory management can be flagged. Identify and whitelist these scripts to prevent unnecessary alerts.
* Scheduled jobs or cron tasks that gather system information for legitimate purposes might be detected. Review and exclude these tasks from the rule to reduce false positives.
* Development or testing environments where frequent system information queries are normal can cause alerts. Consider excluding these environments from monitoring or adjusting the sensitivity of the rule for these contexts.
* Security tools that perform regular system scans may be misidentified. Ensure these tools are recognized and excluded from triggering the rule.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified as part of the unusual system information discovery activity.
* Review and reset credentials for the potentially compromised account to prevent further misuse.
* Conduct a thorough examination of system logs and command history to identify any additional malicious activities or indicators of compromise.
* Apply security patches and updates to the affected system to mitigate any known vulnerabilities that could be exploited for privilege escalation.
* Implement enhanced monitoring on the affected system and similar environments to detect any recurrence of unusual system information discovery activities.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_1450]

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

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)



