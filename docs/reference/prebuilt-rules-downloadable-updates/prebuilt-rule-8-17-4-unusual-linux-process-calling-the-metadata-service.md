---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-linux-process-calling-the-metadata-service.html
---

# Unusual Linux Process Calling the Metadata Service [prebuilt-rule-8-17-4-unusual-linux-process-calling-the-metadata-service]

Looks for anomalous access to the metadata service by an unusual process. The metadata service may be targeted in order to harvest credentials or user data scripts containing secrets.

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

## Investigation guide [_investigation_guide_4613]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Linux Process Calling the Metadata Service**

In cloud environments, the metadata service provides essential instance-specific data, including credentials and configuration scripts. Adversaries may exploit this service by using atypical processes to access sensitive information, potentially leading to credential theft. The detection rule leverages machine learning to identify anomalous process behavior, flagging unusual access patterns indicative of malicious intent.

**Possible investigation steps**

* Review the process name and command line arguments associated with the alert to identify any unusual or suspicious activity.
* Check the user account under which the process is running to determine if it has legitimate access to the metadata service.
* Investigate the process’s parent process to understand the context of how it was initiated and whether it aligns with expected behavior.
* Analyze network logs to verify if the process made any outbound connections to the metadata service and assess the volume and frequency of these requests.
* Cross-reference the process and user information with recent changes or deployments in the environment to rule out any legitimate use cases.
* Examine system logs for any other suspicious activities or anomalies around the time the alert was triggered, such as unauthorized access attempts or privilege escalations.

**False positive analysis**

* Routine system updates or maintenance scripts may access the metadata service, triggering false positives. Users can create exceptions for known update processes to prevent unnecessary alerts.
* Automated backup or monitoring tools might interact with the metadata service as part of their normal operations. Identify these tools and whitelist their processes to reduce false alarms.
* Custom scripts developed in-house for configuration management might access the metadata service. Review these scripts and add them to an exception list if they are verified as non-threatening.
* Cloud management agents provided by the cloud service provider may access the metadata service for legitimate purposes. Verify these agents and exclude them from the detection rule to avoid false positives.
* Development or testing environments often have processes that mimic production behavior, including metadata service access. Ensure these environments are accounted for in the rule configuration to minimize false alerts.

**Response and remediation**

* Isolate the affected instance immediately to prevent further unauthorized access to the metadata service and potential lateral movement within the network.
* Terminate the unusual process accessing the metadata service to stop any ongoing data exfiltration or credential harvesting.
* Conduct a thorough review of access logs and process execution history on the affected instance to identify any additional unauthorized activities or compromised credentials.
* Rotate all credentials and secrets that may have been exposed through the metadata service to mitigate the risk of credential theft and unauthorized access.
* Implement network segmentation and access controls to restrict access to the metadata service, ensuring only authorized processes and users can interact with it.
* Escalate the incident to the security operations team for further investigation and to determine if additional instances or services have been compromised.
* Update and enhance monitoring rules to detect similar anomalous behaviors in the future, focusing on unusual process activities and access patterns to the metadata service.


## Setup [_setup_1445]

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



