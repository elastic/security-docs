---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-sudo-activity.html
---

# Unusual Sudo Activity [unusual-sudo-activity]

Looks for sudo activity from an unusual user context. An unusual sudo user could be due to troubleshooting activity or it could be a sign of credentialed access via compromised accounts.

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
* Tactic: Privilege Escalation
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1158]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Sudo Activity**

Sudo is a command in Unix-like systems that allows permitted users to execute commands as a superuser, providing necessary privileges for administrative tasks. Adversaries may exploit this by using compromised credentials to gain elevated access, potentially bypassing security controls. The *Unusual Sudo Activity* detection rule leverages machine learning to identify deviations from normal sudo usage patterns, flagging potential privilege escalation attempts for further investigation.

**Possible investigation steps**

* Review the user account associated with the unusual sudo activity to determine if it aligns with known administrative roles or if it is typically associated with non-privileged tasks.
* Check the timestamp of the sudo activity to see if it coincides with any known maintenance windows or reported troubleshooting activities.
* Analyze the command executed with sudo to assess whether it is a common administrative command or if it appears suspicious or unnecessary for the user’s role.
* Investigate the source IP address or hostname from which the sudo command was executed to verify if it is a recognized and authorized device.
* Look into recent login activity for the user account to identify any unusual access patterns or locations that could indicate compromised credentials.
* Cross-reference the alert with any other security events or logs around the same time to identify potential indicators of compromise or related malicious activity.

**False positive analysis**

* Administrative troubleshooting activities can trigger false positives. Regularly review and document legitimate administrative tasks that require sudo access to differentiate them from potential threats.
* Developers or IT staff performing routine maintenance may cause alerts. Create exceptions for known maintenance windows or specific user accounts that frequently require elevated privileges.
* Automated scripts or scheduled tasks using sudo might be flagged. Identify and whitelist these scripts or tasks if they are verified as safe and necessary for operations.
* New employees or role changes can lead to unusual sudo activity. Update user roles and permissions promptly to reflect their current responsibilities and reduce unnecessary alerts.
* Temporary access granted for specific projects can appear suspicious. Ensure that temporary access is well-documented and set to expire automatically to prevent lingering false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Revoke or reset the compromised credentials to prevent further misuse and ensure that the affected user account is secured.
* Conduct a thorough review of recent sudo logs and system activity to identify any unauthorized changes or actions taken by the adversary.
* Restore any altered or deleted files from backups, ensuring that the system is returned to its last known good state.
* Apply any necessary security patches or updates to the affected system to close vulnerabilities that may have been exploited.
* Enhance monitoring and logging for sudo activities across all systems to detect similar anomalies in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_730]

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

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)



