---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-network-destination-domain-name.html
---

# Unusual Network Destination Domain Name [unusual-network-destination-domain-name]

A machine learning job detected an unusual network destination domain name. This can be due to initial access, persistence, command-and-control, or exfiltration activity. For example, when a user clicks on a link in a phishing email or opens a malicious document, a request may be sent to download and run a payload from an uncommon web server name. When malware is already running, it may send requests to an uncommon DNS domain the malware uses for command-and-control communication.

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

* Use Case: Threat Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1137]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Network Destination Domain Name**

Machine learning models analyze network traffic to identify atypical domain names, which may indicate malicious activities like phishing or malware communication. Adversaries exploit uncommon domains for initial access or command-and-control. This detection rule leverages ML to flag these anomalies, aiding analysts in identifying potential threats early.

**Possible investigation steps**

* Review the domain name flagged by the alert to determine if it is known for malicious activity or if it is newly registered, using threat intelligence sources and domain reputation services.
* Analyze the network traffic associated with the domain to identify the source IP address and any related communication patterns, such as frequency and data volume.
* Check the user or system that initiated the connection to the unusual domain for any recent changes or suspicious activities, such as software installations or configuration changes.
* Investigate any related alerts or logs that might provide additional context, such as other unusual domain requests or failed login attempts, to identify potential patterns or correlations.
* Assess the endpoint security logs for signs of malware or unauthorized access attempts that could be linked to the unusual domain activity.

**False positive analysis**

* Legitimate software updates or downloads from uncommon domains can trigger false positives. Users should maintain a list of known software vendors and their associated domains to exclude these from alerts.
* Internal testing or development environments may use non-standard domain names. Organizations should document these domains and configure exceptions to prevent unnecessary alerts.
* Newly registered domains for legitimate business purposes might be flagged. Regularly update the list of approved domains as new business initiatives arise.
* Third-party services or APIs that use unique domain names can cause false positives. Identify and whitelist these services to reduce noise in alerts.
* Temporary or one-time use domains for events or campaigns should be monitored and excluded as needed to avoid repeated false positives.

**Response and remediation**

* Isolate the affected system from the network to prevent further communication with the suspicious domain and potential spread of malware.
* Conduct a thorough scan of the isolated system using updated antivirus and anti-malware tools to identify and remove any malicious software.
* Review and analyze network logs to identify any other systems that may have communicated with the unusual domain and apply similar isolation and scanning procedures to those systems.
* Change passwords and credentials associated with the affected system and any potentially compromised accounts to prevent unauthorized access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional containment measures are necessary.
* Implement network-level blocking of the identified unusual domain across the organization to prevent future access attempts.
* Update threat intelligence feeds and detection systems with indicators of compromise (IOCs) related to the unusual domain to enhance future detection capabilities.


## Setup [_setup_715]

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


