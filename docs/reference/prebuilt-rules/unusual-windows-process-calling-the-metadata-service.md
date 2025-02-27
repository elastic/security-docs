---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-windows-process-calling-the-metadata-service.html
---

# Unusual Windows Process Calling the Metadata Service [unusual-windows-process-calling-the-metadata-service]

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

## Investigation guide [_investigation_guide_1165]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Windows Process Calling the Metadata Service**

In cloud environments, the metadata service provides essential instance information, including credentials and configuration data. Adversaries may exploit this by using atypical Windows processes to access the service, aiming to extract sensitive information. The detection rule leverages machine learning to identify anomalies in process behavior, flagging potential credential access attempts by unusual processes.

**Possible investigation steps**

* Review the process name and command line arguments associated with the alert to identify any unusual or suspicious activity.
* Check the parent process of the flagged process to understand the context of how it was initiated and assess if it aligns with expected behavior.
* Investigate the user account under which the process was executed to determine if it has legitimate access to the metadata service or if it has been compromised.
* Analyze network logs to identify any outbound connections to the metadata service from the flagged process, noting any unusual patterns or destinations.
* Cross-reference the process and user activity with recent changes or deployments in the environment to rule out false positives related to legitimate administrative actions.
* Consult threat intelligence sources to see if the process or command line arguments have been associated with known malicious activity or campaigns.

**False positive analysis**

* Routine system updates or maintenance scripts may trigger the rule. Review the process details and verify if they align with scheduled maintenance activities. If confirmed, consider adding these processes to an exception list.
* Legitimate software or security tools that access the metadata service for configuration purposes might be flagged. Identify these tools and create exceptions for their known processes to prevent future alerts.
* Automated backup or monitoring solutions that interact with the metadata service could be misidentified as threats. Validate these processes and exclude them if they are part of authorized operations.
* Custom scripts developed in-house for cloud management tasks may access the metadata service. Ensure these scripts are documented and, if safe, add them to the list of exceptions to reduce false positives.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate the unusual process accessing the metadata service to stop any ongoing credential harvesting attempts.
* Conduct a thorough review of the system’s event logs and process history to identify any additional indicators of compromise or related malicious activity.
* Change all credentials that may have been exposed or accessed through the metadata service to mitigate the risk of unauthorized access.
* Implement network segmentation to limit access to the metadata service, ensuring only authorized processes and users can interact with it.
* Escalate the incident to the security operations center (SOC) for further analysis and to determine if the threat is part of a larger attack campaign.
* Update and enhance endpoint detection and response (EDR) solutions to improve monitoring and alerting for similar anomalous process behaviors in the future.


## Setup [_setup_737]

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



