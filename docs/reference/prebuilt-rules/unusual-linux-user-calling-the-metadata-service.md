---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-linux-user-calling-the-metadata-service.html
---

# Unusual Linux User Calling the Metadata Service [unusual-linux-user-calling-the-metadata-service]

Looks for anomalous access to the cloud platform metadata service by an unusual user. The metadata service may be targeted in order to harvest credentials or user data scripts containing secrets.

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
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1130]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Linux User Calling the Metadata Service**

Cloud platforms provide a metadata service that allows instances to access configuration data, including credentials. Adversaries may exploit this by using unusual Linux users to query the service, aiming to extract sensitive information. The detection rule leverages machine learning to identify anomalous access patterns, focusing on credential access tactics, thus alerting analysts to potential threats.

**Possible investigation steps**

* Review the alert details to identify the specific Linux user account that accessed the metadata service and the timestamp of the activity.
* Check the user’s login history and recent activity on the system to determine if the access pattern is consistent with their normal behavior or if it appears suspicious.
* Investigate the source IP address and geolocation associated with the metadata service access to identify any anomalies or unexpected locations.
* Examine system logs and audit trails for any additional unauthorized or unusual access attempts around the same time frame.
* Verify if the user account has legitimate reasons to access the metadata service, such as running specific applications or scripts that require metadata information.
* Assess whether there have been any recent changes to user permissions or roles that could explain the access, and ensure that these changes were authorized.
* If suspicious activity is confirmed, consider isolating the affected instance and user account to prevent further unauthorized access while conducting a deeper investigation.

**False positive analysis**

* Routine administrative scripts may access the metadata service for legitimate configuration purposes. To handle this, identify and whitelist these scripts to prevent unnecessary alerts.
* Automated backup or monitoring tools might query the metadata service as part of their normal operations. Exclude these tools by adding them to an exception list based on their user accounts or process identifiers.
* Scheduled tasks or cron jobs that require metadata access for updates or maintenance can trigger false positives. Review and document these tasks, then configure the rule to ignore these specific access patterns.
* Development or testing environments often simulate metadata service access to mimic production scenarios. Ensure these environments are recognized and excluded from the rule to avoid false alerts.
* Temporary user accounts created for specific projects or tasks may access the metadata service. Regularly audit these accounts and adjust the rule to exclude them if their access is deemed non-threatening.

**Response and remediation**

* Immediately isolate the affected Linux instance from the network to prevent further unauthorized access or data exfiltration.
* Revoke any credentials or tokens that may have been exposed or accessed through the metadata service to prevent misuse.
* Conduct a thorough review of the instance’s user accounts and permissions, removing any unauthorized or suspicious accounts and tightening access controls.
* Analyze system logs and metadata service access logs to identify the source and scope of the breach, focusing on the unusual user activity.
* Restore the affected instance from a known good backup if any unauthorized changes or malware are detected.
* Implement additional monitoring and alerting for metadata service access, particularly for unusual user accounts, to detect similar threats in the future.
* Escalate the incident to the security operations team for further investigation and to determine if additional instances or services are affected.


## Setup [_setup_711]

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

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Unsecured Credentials
    * ID: T1552
    * Reference URL: [https://attack.mitre.org/techniques/T1552/](https://attack.mitre.org/techniques/T1552/)

* Sub-technique:

    * Name: Cloud Instance Metadata API
    * ID: T1552.005
    * Reference URL: [https://attack.mitre.org/techniques/T1552/005/](https://attack.mitre.org/techniques/T1552/005/)



