---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-login-activity.html
---

# Unusual Login Activity [unusual-login-activity]

Identifies an unusually high number of authentication attempts.

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

## Investigation guide [_investigation_guide_1133]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Login Activity**

The *Unusual Login Activity* detection leverages machine learning to identify anomalies in authentication patterns, flagging potential brute force attacks. Adversaries exploit credential access by attempting numerous logins to gain unauthorized entry. This rule assesses login frequency and patterns, alerting analysts to deviations indicative of credential abuse, thus enhancing threat detection and identity audit processes.

**Possible investigation steps**

* Review the source IP addresses associated with the unusual login attempts to determine if they are known or suspicious.
* Check the user accounts involved in the alert for any recent changes or unusual activity, such as password resets or privilege escalations.
* Analyze the timestamps of the login attempts to identify patterns or timeframes that may indicate automated or scripted attacks.
* Correlate the login attempts with other security events or logs to identify any concurrent suspicious activities, such as failed login attempts or access to sensitive resources.
* Investigate the geographic locations of the login attempts to see if they align with the user’s typical login behavior or if they suggest potential compromise.
* Assess the risk score and severity of the alert in the context of the organization’s security posture and any ongoing threats or incidents.

**False positive analysis**

* High login activity from automated scripts or scheduled tasks can trigger false positives. Identify and whitelist these known scripts to prevent unnecessary alerts.
* Employees using shared accounts may cause an increase in login attempts. Implement user-specific accounts and monitor shared account usage to reduce false positives.
* Frequent logins from IT personnel conducting routine maintenance can be misinterpreted as unusual activity. Exclude these users or adjust thresholds for specific roles to minimize false alerts.
* Users with legitimate reasons for high login frequency, such as customer support staff, should be identified and their activity patterns analyzed to adjust detection parameters accordingly.
* Remote workers using VPNs or accessing systems from multiple locations might trigger alerts. Consider location-based exceptions for known remote access points to avoid false positives.

**Response and remediation**

* Immediately isolate the affected user accounts to prevent further unauthorized access and contain the threat.
* Reset passwords for the compromised accounts and enforce multi-factor authentication (MFA) to enhance security.
* Conduct a thorough review of recent login activity and access logs to identify any unauthorized access or data exfiltration.
* Notify the security operations team to monitor for any further suspicious activity and ensure continuous surveillance of the affected systems.
* Escalate the incident to the incident response team if there is evidence of data compromise or if the attack persists despite initial containment efforts.
* Implement additional monitoring rules to detect similar brute force attempts in the future, focusing on login frequency and patterns.
* Review and update access controls and authentication policies to prevent recurrence, ensuring they align with best practices for credential security.


## Setup [_setup_714]

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



