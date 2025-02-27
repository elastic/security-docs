---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-linux-network-port-activity.html
---

# Unusual Linux Network Port Activity [unusual-linux-network-port-activity]

Identifies unusual destination port activity that can indicate command-and-control, persistence mechanism, or data exfiltration activity. Rarely used destination port activity is generally unusual in Linux fleets, and can indicate unauthorized access or threat actor activity.

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
* OS: Linux
* Use Case: Threat Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1126]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Linux Network Port Activity**

In Linux environments, network ports facilitate communication between applications and services. Adversaries may exploit rarely used ports for covert command-and-control, persistence, or data exfiltration, bypassing standard monitoring. The *Unusual Linux Network Port Activity* detection rule leverages machine learning to identify anomalies in port usage, flagging potential unauthorized access or threat actor activity by highlighting deviations from typical network behavior.

**Possible investigation steps**

* Review the alert details to identify the specific unusual destination port and the associated source and destination IP addresses.
* Check historical network logs to determine if the identified port has been used previously and assess the frequency and context of its usage.
* Investigate the source IP address to determine if it is associated with known internal systems or if it is an external or unexpected source.
* Analyze the destination IP address to verify if it is a legitimate endpoint within the network or an external entity that requires further scrutiny.
* Correlate the unusual port activity with any recent changes or updates in the network environment that might explain the anomaly.
* Examine any related process or application logs on the involved Linux systems to identify the application or service responsible for the network activity.
* Consider reaching out to the system owner or administrator for additional context or to verify if the activity is expected or authorized.

**False positive analysis**

* Routine administrative tasks may trigger alerts when using non-standard ports for legitimate purposes. Users can create exceptions for known administrative tools and scripts that consistently use these ports.
* Internal applications or services might use uncommon ports for inter-service communication. Identify these applications and whitelist their port usage to prevent unnecessary alerts.
* Security tools and monitoring solutions sometimes scan or probe network ports as part of their operations. Recognize these tools and exclude their activities from the rule to avoid false positives.
* Development and testing environments often experiment with various port configurations. Establish a separate monitoring profile for these environments to reduce noise in production alerts.
* Custom or legacy applications may operate on non-standard ports due to historical configurations. Document these applications and adjust the rule to accommodate their expected behavior.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Conduct a thorough review of the system’s network connections and terminate any suspicious or unauthorized connections.
* Analyze system logs to identify any malicious processes or scripts that may have been executed, and remove or quarantine any identified threats.
* Change all credentials associated with the affected system, especially if there is any indication of credential compromise.
* Restore the system from a known good backup if any unauthorized changes or malware are detected.
* Implement network segmentation to limit the exposure of critical systems to potential threats and reduce the risk of lateral movement.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_707]

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


