---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-spike-in-network-traffic.html
---

# Spike in Network Traffic [prebuilt-rule-8-17-4-spike-in-network-traffic]

A machine learning job detected an unusually large spike in network traffic. Such a burst of traffic, if not caused by a surge in business activity, can be due to suspicious or malicious activity. Large-scale data exfiltration may produce a burst of network traffic; this could also be due to unusually large amounts of reconnaissance or enumeration traffic. Denial-of-service attacks or traffic floods may also produce such a surge in traffic.

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

* Use Case: Threat Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4629]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Spike in Network Traffic**

Machine learning models analyze network traffic patterns to identify anomalies, such as unexpected spikes. These spikes may indicate malicious activities like data exfiltration or denial-of-service attacks. Adversaries exploit network vulnerabilities to flood traffic or extract data. The *Spike in Network Traffic* rule leverages ML to flag unusual traffic surges, aiding in early threat detection and response.

**Possible investigation steps**

* Review the timestamp and duration of the traffic spike to determine if it correlates with any scheduled business activities or known events.
* Analyze the source and destination IP addresses involved in the traffic spike to identify any unfamiliar or suspicious entities.
* Examine the types of network protocols and services involved in the spike to assess if they align with typical network usage patterns.
* Check for any recent changes in network configurations or security policies that might explain the unusual traffic patterns.
* Investigate any associated user accounts or devices to determine if they have been compromised or are exhibiting unusual behavior.
* Cross-reference the spike with other security alerts or logs to identify potential patterns or related incidents.

**False positive analysis**

* Business-related traffic surges: Regular spikes due to legitimate business activities, such as marketing campaigns or software updates, can trigger false positives. Users should analyze historical traffic patterns and create exceptions for known business events.
* Scheduled data backups: Routine data backups can cause significant network traffic. Users can exclude these by identifying backup schedules and configuring the rule to ignore traffic during these times.
* Software updates and patches: Large-scale updates from software vendors can lead to temporary traffic spikes. Users should maintain a list of update schedules and whitelist these events to prevent false alerts.
* Internal network scans: Regular security scans or inventory checks within the organization may cause traffic spikes. Users should document these activities and adjust the rule to recognize them as non-threatening.
* Cloud service synchronization: Synchronization activities with cloud services can generate high traffic volumes. Users should identify and exclude these regular sync patterns to reduce false positives.

**Response and remediation**

* Immediately isolate affected systems from the network to prevent further data exfiltration or traffic flooding.
* Conduct a thorough analysis of network logs to identify the source and destination of the traffic spike, focusing on any unauthorized or suspicious IP addresses.
* Block identified malicious IP addresses and domains at the firewall and update intrusion prevention systems to prevent further access.
* If data exfiltration is suspected, perform a data integrity check to assess any potential data loss or compromise.
* Notify the incident response team to assess the situation and determine if further escalation is necessary, including potential involvement of law enforcement if data theft is confirmed.
* Review and update network access controls and permissions to ensure only authorized users and devices have access to sensitive data and systems.
* Implement enhanced monitoring and alerting for similar traffic patterns to improve early detection and response to future incidents.


## Setup [_setup_1461]

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


