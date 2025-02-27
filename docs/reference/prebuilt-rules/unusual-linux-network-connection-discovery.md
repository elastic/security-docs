---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-linux-network-connection-discovery.html
---

# Unusual Linux Network Connection Discovery [unusual-linux-network-connection-discovery]

Looks for commands related to system network connection discovery from an unusual user context. This can be due to uncommon troubleshooting activity or due to a compromised account. A compromised account may be used by a threat actor to engage in system network connection discovery in order to increase their understanding of connected services and systems. This information may be used to shape follow-up behaviors such as lateral movement or additional discovery.

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

## Investigation guide [_investigation_guide_1125]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Linux Network Connection Discovery**

In Linux environments, network connection discovery tools help administrators understand system connectivity. Adversaries exploit these tools to map networks, aiding in lateral movement and further attacks. The detection rule leverages machine learning to identify atypical usage patterns by unusual users, signaling potential account compromise or unauthorized network probing activities.

**Possible investigation steps**

* Review the alert details to identify the specific user account and the command executed that triggered the alert.
* Check the user’s activity history to determine if this behavior is consistent with their normal usage patterns or if it is anomalous.
* Investigate the source IP address and hostname associated with the command execution to verify if they are known and trusted within the network.
* Examine system logs for any additional suspicious activities or commands executed by the same user account around the time of the alert.
* Assess the user’s access permissions and recent changes to their account to identify any unauthorized modifications or potential compromise.
* Correlate the alert with other security events or alerts to determine if this activity is part of a larger attack pattern or campaign.

**False positive analysis**

* Routine administrative tasks by system administrators can trigger alerts. Regularly review and whitelist known administrator accounts performing legitimate network discovery.
* Automated scripts or monitoring tools that perform network checks may be flagged. Identify and exclude these scripts from triggering alerts by adding them to an exception list.
* Uncommon troubleshooting activities by support teams might be misidentified. Document and approve these activities to prevent false positives.
* Scheduled maintenance activities involving network discovery should be accounted for. Create a schedule-based exception to avoid unnecessary alerts during these periods.
* New employees or contractors performing legitimate network discovery as part of their onboarding process can be mistaken for threats. Ensure their activities are monitored and approved by the IT department.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious processes or sessions initiated by the unusual user to halt ongoing network discovery activities.
* Conduct a thorough review of the affected user’s account activity and permissions to identify any unauthorized changes or access patterns.
* Reset the credentials of the compromised account and enforce multi-factor authentication to prevent further unauthorized access.
* Analyze network logs and system logs to identify any additional systems that may have been accessed or probed by the threat actor.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or accounts are compromised.
* Update and enhance network monitoring and alerting rules to detect similar unauthorized network discovery activities in the future.


## Setup [_setup_706]

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

    * Name: System Network Connections Discovery
    * ID: T1049
    * Reference URL: [https://attack.mitre.org/techniques/T1049/](https://attack.mitre.org/techniques/T1049/)



