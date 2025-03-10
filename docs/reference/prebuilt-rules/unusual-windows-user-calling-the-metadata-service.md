---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-windows-user-calling-the-metadata-service.html
---

# Unusual Windows User Calling the Metadata Service [unusual-windows-user-calling-the-metadata-service]

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
* OS: Windows
* Use Case: Threat Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1168]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Windows User Calling the Metadata Service**

Cloud platforms provide a metadata service that allows instances to access configuration data, including credentials. Adversaries may exploit this by using compromised Windows accounts to query the service, aiming to harvest sensitive information. The detection rule leverages machine learning to identify atypical access patterns by Windows users, flagging potential credential access attempts.

**Possible investigation steps**

* Review the alert details to identify the specific Windows user account involved in the unusual access to the metadata service.
* Check the timestamp of the access attempt to correlate with any known scheduled tasks or legitimate user activities.
* Investigate the source IP address and device from which the metadata service was accessed to determine if it aligns with expected user behavior or known assets.
* Examine recent login and access logs for the identified user account to detect any other suspicious activities or anomalies.
* Assess whether there have been any recent changes to the user’s permissions or roles that could explain the access attempt.
* Look for any other alerts or incidents involving the same user account or device to identify potential patterns of malicious behavior.
* Consult with the user or their manager to verify if the access was legitimate or if the account may have been compromised.

**False positive analysis**

* Routine administrative tasks by IT personnel may trigger alerts. Review access logs to confirm legitimate administrative actions and consider whitelisting specific user accounts or IP addresses.
* Automated scripts or scheduled tasks that query the metadata service for configuration updates can be mistaken for suspicious activity. Identify these scripts and exclude them from the rule by adding them to an exception list.
* Cloud management tools that regularly access the metadata service for monitoring or configuration purposes might be flagged. Verify these tools and create exceptions for their known access patterns.
* Instances where legitimate software updates or patch management processes access the metadata service should be reviewed. Document these processes and exclude them from triggering alerts.
* Temporary access by third-party vendors or consultants may appear unusual. Ensure their access is documented and create temporary exceptions during their engagement period.

**Response and remediation**

* Immediately isolate the affected Windows system from the network to prevent further unauthorized access to the metadata service.
* Revoke any potentially compromised credentials identified during the investigation and issue new credentials to affected users.
* Conduct a thorough review of access logs to identify any unauthorized data access or exfiltration attempts from the metadata service.
* Implement additional monitoring on the affected system and similar systems to detect any further anomalous access attempts.
* Escalate the incident to the security operations center (SOC) for a deeper investigation into potential lateral movement or other compromised systems.
* Apply security patches and updates to the affected system to address any vulnerabilities that may have been exploited.
* Review and enhance access controls and permissions for the metadata service to ensure only authorized users can access sensitive information.


## Setup [_setup_740]

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



