---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/spike-in-successful-logon-events-from-a-source-ip.html
---

# Spike in Successful Logon Events from a Source IP [spike-in-successful-logon-events-from-a-source-ip]

A machine learning job found an unusually large spike in successful authentication events from a particular source IP address. This can be due to password spraying, user enumeration or brute force activity.

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
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_947]

**Triage and analysis**

**Investigating Spike in Successful Logon Events from a Source IP**

This rule uses a machine learning job to detect a substantial spike in successful authentication events. This could indicate post-exploitation activities that aim to test which hosts, services, and other resources the attacker can access with the compromised credentials.

**Possible investigation steps**

* Identify the specifics of the involved assets, such as role, criticality, and associated users.
* Check if the authentication comes from different sources.
* Use the historical data available to determine if the same behavior happened in the past.
* Investigate other alerts associated with the involved users during the past 48 hours.
* Check whether the involved credentials are used in automation or scheduled tasks.
* If this activity is suspicious, contact the account owner and confirm whether they are aware of it.

**False positive analysis**

* Understand the context of the authentications by contacting the asset owners. If this activity is related to a new business process or newly implemented (approved) technology, consider adding exceptions — preferably with a combination of user and source conditions.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_601]

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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Domain Accounts
    * ID: T1078.002
    * Reference URL: [https://attack.mitre.org/techniques/T1078/002/](https://attack.mitre.org/techniques/T1078/002/)

* Sub-technique:

    * Name: Local Accounts
    * ID: T1078.003
    * Reference URL: [https://attack.mitre.org/techniques/T1078/003/](https://attack.mitre.org/techniques/T1078/003/)



