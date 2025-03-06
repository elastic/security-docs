---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/spike-in-logon-events.html
---

# Spike in Logon Events [spike-in-logon-events]

A machine learning job found an unusually large spike in successful authentication events. This can be due to password spraying, user enumeration or brute force activity.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)

**Tags**:

* Use Case: Identity and Access Audit
* Use Case: Threat Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_940]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Spike in Logon Events**

The *Spike in Logon Events* detection leverages machine learning to identify anomalies in authentication patterns, signaling potential threats like password spraying or brute force attacks. Adversaries exploit these methods to gain unauthorized access by overwhelming systems with login attempts. This rule detects unusual surges in successful logins, indicating possible credential access tactics, and aids in preemptive threat mitigation.

**Possible investigation steps**

* Review the timestamp and source of the spike in logon events to determine the time frame and systems affected.
* Analyze the user accounts involved in the spike to identify any patterns or anomalies, such as accounts with multiple logins from different locations or IP addresses.
* Check for any recent changes in user permissions or roles that could explain the increase in logon events.
* Investigate the IP addresses associated with the logon events to identify any known malicious sources or unusual geographic locations.
* Correlate the logon events with other security alerts or logs, such as failed login attempts, to identify potential password spraying or brute force activities.
* Assess whether there are any concurrent alerts or indicators of compromise that could suggest a broader attack campaign.

**False positive analysis**

* High-volume legitimate logins from automated systems or scripts can trigger false positives. Identify and whitelist these systems to prevent unnecessary alerts.
* Scheduled batch processes or system maintenance activities may cause spikes in logon events. Exclude these known activities by setting up exceptions based on time and source.
* Users with roles that require frequent logins, such as IT administrators or customer support agents, might be flagged. Create user-based exceptions for these roles to reduce false positives.
* Integration with third-party services that authenticate frequently can lead to detection triggers. Review and exclude these services from the rule to avoid misclassification.
* Consider adjusting the sensitivity of the machine learning model if certain patterns are consistently flagged as anomalies but are verified as legitimate.

**Response and remediation**

* Immediately isolate the affected user accounts to prevent further unauthorized access. This can be done by disabling the accounts or resetting passwords.
* Conduct a thorough review of recent authentication logs to identify any other accounts that may have been compromised or targeted.
* Implement multi-factor authentication (MFA) for all user accounts to add an additional layer of security against unauthorized access.
* Notify the security operations team to monitor for any further suspicious logon activities and to ensure that the threat is contained.
* Escalate the incident to the incident response team if there is evidence of a broader attack or if sensitive data may have been accessed.
* Review and update access controls and permissions to ensure that users have the minimum necessary access to perform their roles.
* Enhance monitoring and alerting mechanisms to detect similar spikes in logon events in the future, ensuring rapid response to potential threats.


## Setup [_setup_594]

**Setup**

This rule requires the installation of associated Machine Learning jobs, as well as data coming in from one of the following integrations: - Elastic Defend - Auditd Manager - System

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

**System Integration Setup**

The System integration allows you to collect system logs and metrics from your servers with Elastic Agent.

**The following steps should be executed in order to add the Elastic Agent System integration "system" to your system:**

* Go to the Kibana home page and click “Add integrations”.
* In the query bar, search for “System” and select the integration to see more details about it.
* Click “Add System”.
* Configure the integration name and optionally add a description.
* Review optional and advanced settings accordingly.
* Add the newly installed “system” to an existing or a new agent policy, and deploy the agent on your system from which system log files are desirable.
* Click “Save and Continue”.
* For more details on the integration refer to the [helper guide](https://docs.elastic.co/integrations/system).

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Brute Force
    * ID: T1110
    * Reference URL: [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)



