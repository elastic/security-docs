---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-dns-activity.html
---

# Unusual DNS Activity [unusual-dns-activity]

A machine learning job detected a rare and unusual DNS query that indicate network activity with unusual DNS domains. This can be due to initial access, persistence, command-and-control, or exfiltration activity. For example, when a user clicks on a link in a phishing email or opens a malicious document, a request may be sent to download and run a payload from an uncommon domain. When malware is already running, it may send requests to an uncommon DNS domain the malware uses for command-and-control communication.

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
* Tactic: Command and Control
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1108]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual DNS Activity**

DNS is crucial for translating domain names into IP addresses, enabling network communication. Adversaries exploit DNS by using rare domains for malicious activities like phishing or command-and-control. The *Unusual DNS Activity* detection rule leverages machine learning to identify atypical DNS queries, signaling potential threats such as unauthorized access or data exfiltration.

**Possible investigation steps**

* Review the DNS query logs to identify the specific rare domain that triggered the alert and determine its reputation using threat intelligence sources.
* Analyze the source IP address associated with the unusual DNS query to identify the device or user responsible for the activity.
* Check for any recent changes or anomalies in the network activity of the identified device or user, such as unusual login times or access to sensitive data.
* Investigate any related alerts or logs that might indicate a broader pattern of suspicious activity, such as multiple rare domain queries or connections to known malicious IP addresses.
* Examine endpoint security logs on the affected device for signs of malware or unauthorized software that could be responsible for the unusual DNS activity.
* Assess whether the unusual DNS activity aligns with known tactics, techniques, and procedures (TTPs) associated with command-and-control or data exfiltration, referencing the MITRE ATT&CK framework for guidance.

**False positive analysis**

* Legitimate software updates may trigger unusual DNS queries as they contact uncommon domains for downloading updates. Users can create exceptions for known update servers to reduce false positives.
* Internal applications using dynamic DNS services might generate rare DNS queries. Identifying and whitelisting these services can help in minimizing false alerts.
* Third-party security tools or monitoring solutions may use unique DNS queries for their operations. Verify and exclude these tools from the detection rule to prevent unnecessary alerts.
* Cloud services often use diverse and uncommon domains for legitimate operations. Regularly review and update the list of trusted cloud service domains to avoid false positives.
* New or infrequently accessed legitimate websites may appear as unusual. Users should monitor and whitelist these domains if they are confirmed to be safe and necessary for business operations.

**Response and remediation**

* Isolate the affected system from the network to prevent further communication with the suspicious DNS domain and potential data exfiltration.
* Conduct a thorough scan of the isolated system using updated antivirus and anti-malware tools to identify and remove any malicious software.
* Review and block the identified unusual DNS domain at the network perimeter to prevent other systems from communicating with it.
* Analyze logs and network traffic to identify any other systems that may have communicated with the same unusual DNS domain and apply similar containment measures.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.
* Restore the affected system from a known good backup if malware removal is not possible or if system integrity is in question.
* Update and enhance DNS monitoring rules to detect similar unusual DNS activity in the future, ensuring rapid identification and response to potential threats.


## Setup [_setup_696]

**Setup**

This rule requires the installation of associated Machine Learning jobs, as well as data coming in from one of the following integrations: - Elastic Defend - Network Packet Capture

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

**Network Packet Capture Integration Setup**

The Network Packet Capture integration sniffs network packets on a host and dissects known protocols. Monitoring the network traffic is critical to gaining observability and securing your environment — ensuring high levels of performance and security. The Network Packet Capture integration captures the network traffic between your application servers, decodes common application layer protocols and records the interesting fields for each transaction.

**The following steps should be executed in order to add the Elastic Agent System integration "network_traffic" to your system:**

* Go to the Kibana home page and click “Add integrations”.
* In the query bar, search for “Network Packet Capture” and select the integration to see more details about it.
* Click “Add Network Packet Capture”.
* Configure the integration name and optionally add a description.
* Review optional and advanced settings accordingly.
* Add the newly installed “network_traffic” to an existing or a new agent policy, and deploy the agent on your system from which network log files are desirable.
* Click “Save and Continue”.
* For more details on the integration refer to the [helper guide](https://docs.elastic.co/integrations/network_traffic).

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Application Layer Protocol
    * ID: T1071
    * Reference URL: [https://attack.mitre.org/techniques/T1071/](https://attack.mitre.org/techniques/T1071/)

* Sub-technique:

    * Name: DNS
    * ID: T1071.004
    * Reference URL: [https://attack.mitre.org/techniques/T1071/004/](https://attack.mitre.org/techniques/T1071/004/)



