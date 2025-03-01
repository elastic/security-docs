---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-windows-user-privilege-elevation-activity.html
---

# Unusual Windows User Privilege Elevation Activity [unusual-windows-user-privilege-elevation-activity]

A machine learning job detected an unusual user context switch, using the runas command or similar techniques, which can indicate account takeover or privilege escalation using compromised accounts. Privilege elevation using tools like runas are more commonly used by domain and network administrators than by regular Windows users.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/reference/security/prebuilt-jobs.md](/reference/prebuilt-jobs.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Tactic: Privilege Escalation
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1169]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Windows User Privilege Elevation Activity**

In Windows environments, privilege elevation tools like *runas* allow users to execute programs with different user credentials, typically used by administrators. Adversaries exploit this to gain elevated access, often indicating account compromise. The detection rule leverages machine learning to identify atypical usage patterns of such tools, flagging potential unauthorized privilege escalation attempts.

**Possible investigation steps**

* Review the specific user account involved in the alert to determine if it is a regular user or an administrator, as privilege elevation is more common among administrators.
* Check the timestamp of the alert to correlate with any known scheduled tasks or administrative activities that might explain the use of privilege elevation tools.
* Investigate the source IP address and device from which the privilege elevation attempt was made to verify if it aligns with the user’s typical access patterns.
* Examine recent login activity for the user account to identify any unusual or unauthorized access attempts that could indicate account compromise.
* Look for any other security alerts or logs related to the same user or device around the time of the alert to gather additional context on potential malicious activity.
* Assess whether there have been any recent changes to user permissions or group memberships that could have facilitated the privilege elevation.

**False positive analysis**

* Regular administrative tasks by domain or network administrators can trigger false positives. To manage this, create exceptions for known administrator accounts frequently using the runas command.
* Scheduled tasks or scripts that require privilege elevation might be flagged. Identify and exclude these tasks from monitoring if they are verified as safe and necessary for operations.
* Software updates or installations that require elevated privileges can also cause alerts. Maintain a list of approved software and update processes to exclude them from triggering the rule.
* Training or testing environments where privilege elevation is part of routine operations may generate false positives. Exclude these environments from the rule’s scope to prevent unnecessary alerts.
* Third-party applications that use privilege elevation for legitimate purposes should be reviewed and, if deemed safe, added to an exception list to avoid repeated false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Revoke any elevated privileges granted to the compromised account and reset its password to prevent further misuse.
* Conduct a thorough review of recent activity logs for the affected account to identify any unauthorized actions or data access.
* Notify the security team and relevant stakeholders about the incident for awareness and potential escalation.
* Restore any altered or compromised system configurations to their original state using backups or system snapshots.
* Implement additional monitoring on the affected system and account to detect any further suspicious activity.
* Review and update access controls and privilege management policies to minimize the risk of similar incidents in the future.


## Setup [_setup_741]

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

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)



