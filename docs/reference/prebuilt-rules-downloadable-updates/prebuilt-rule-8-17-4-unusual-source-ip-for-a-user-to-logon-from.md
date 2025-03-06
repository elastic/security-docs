---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-source-ip-for-a-user-to-logon-from.html
---

# Unusual Source IP for a User to Logon from [prebuilt-rule-8-17-4-unusual-source-ip-for-a-user-to-logon-from]

A machine learning job detected a user logging in from an IP address that is unusual for the user. This can be due to credentialed access via a compromised account when the user and the threat actor are in different locations. An unusual source IP address for a username could also be due to lateral movement when a compromised account is used to pivot between hosts.

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
* Tactic: Initial Access
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4624]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Source IP for a User to Logon from**

Machine learning models analyze login patterns to identify atypical IP addresses for users, which may indicate compromised accounts or lateral movement by threat actors. Adversaries exploit valid credentials to access systems from unexpected locations. This detection rule flags such anomalies, aiding in early identification of unauthorized access attempts, thereby enhancing security posture.

**Possible investigation steps**

* Review the login details to identify the unusual source IP address and compare it with the user’s typical login locations and times.
* Check the geolocation of the unusual IP address to determine if it aligns with any known travel or business activities of the user.
* Analyze the user’s recent activity logs to identify any other suspicious behavior or anomalies that might indicate account compromise.
* Investigate if there are any other users or systems that have logged in from the same unusual IP address, which could suggest lateral movement.
* Contact the user to verify if they recognize the login activity and if they have recently traveled or used a VPN that might explain the unusual IP address.
* Cross-reference the unusual IP address with threat intelligence sources to determine if it is associated with known malicious activity.

**False positive analysis**

* Users frequently traveling or working remotely may trigger false positives due to legitimate logins from various locations. To manage this, create exceptions for known travel patterns or remote work IP ranges.
* Employees using VPNs or proxy services can appear to log in from unusual IP addresses. Identify and whitelist IP ranges associated with company-approved VPNs or proxies.
* Shared accounts used by multiple users across different locations can generate alerts. Implement stricter access controls or assign unique credentials to each user to reduce false positives.
* Automated systems or scripts that log in from different IP addresses might be flagged. Document and exclude these systems from the rule if they are verified as non-threatening.
* Regularly review and update the list of excluded IP addresses to ensure that only legitimate exceptions are maintained, reducing the risk of overlooking genuine threats.

**Response and remediation**

* Immediately isolate the affected user account by disabling it to prevent further unauthorized access.
* Conduct a password reset for the compromised account and ensure the new password adheres to strong security policies.
* Review and terminate any active sessions associated with the unusual IP address to cut off any ongoing unauthorized access.
* Analyze logs to identify any lateral movement or additional compromised accounts and isolate those accounts as necessary.
* Notify the user of the suspicious activity and verify if they recognize the unusual IP address or if they have recently traveled.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or accounts have been affected.
* Implement IP whitelisting or geofencing rules to restrict access from unexpected locations, enhancing future detection and prevention.


## Setup [_setup_1456]

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

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)



