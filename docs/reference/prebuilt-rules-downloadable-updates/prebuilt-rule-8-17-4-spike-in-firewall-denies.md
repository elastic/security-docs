---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-spike-in-firewall-denies.html
---

# Spike in Firewall Denies [prebuilt-rule-8-17-4-spike-in-firewall-denies]

A machine learning job detected an unusually large spike in network traffic that was denied by network access control lists (ACLs) or firewall rules. Such a burst of denied traffic is usually caused by either 1) a mis-configured application or firewall or 2) suspicious or malicious activity. Unsuccessful attempts at network transit, in order to connect to command-and-control (C2), or engage in data exfiltration, may produce a burst of failed connections. This could also be due to unusually large amounts of reconnaissance or enumeration traffic. Denial-of-service attacks or traffic floods may also produce such a surge in traffic.

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

## Investigation guide [_investigation_guide_4628]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Spike in Firewall Denies**

Firewalls and ACLs are critical in controlling network traffic, blocking unauthorized access. Adversaries may exploit misconfigurations or launch attacks like reconnaissance or denial-of-service to overwhelm these defenses. The *Spike in Firewall Denies* detection rule leverages machine learning to identify unusual surges in denied traffic, signaling potential misconfigurations or malicious activities.

**Possible investigation steps**

* Review the time frame and source IP addresses associated with the spike in denied traffic to identify any patterns or anomalies.
* Check the firewall and ACL logs for any recent changes or misconfigurations that could have led to the increase in denied traffic.
* Investigate the destination IP addresses and ports targeted by the denied traffic to determine if they are associated with known malicious activity or if they are legitimate services.
* Analyze the volume and frequency of the denied requests to assess whether they align with typical denial-of-service attack patterns or reconnaissance activities.
* Correlate the denied traffic with other security alerts or logs to identify any related suspicious activities or potential indicators of compromise within the network.

**False positive analysis**

* Routine network scans by security tools or IT teams may trigger spikes in denied traffic. Regularly review and whitelist known IP addresses or tools to prevent these from being flagged.
* Misconfigured applications that frequently attempt unauthorized access can cause false positives. Identify and correct these configurations to reduce unnecessary alerts.
* Legitimate but high-volume business applications might generate traffic patterns similar to reconnaissance activities. Monitor and document these applications, and create exceptions for their traffic patterns.
* Scheduled maintenance or updates can lead to temporary spikes in denied traffic. Coordinate with IT teams to anticipate these events and adjust monitoring rules accordingly.
* Internal network changes, such as new device deployments or network architecture updates, might cause unexpected traffic patterns. Ensure these changes are communicated and accounted for in the firewall rules to minimize false positives.

**Response and remediation**

* Immediately isolate affected systems or segments of the network to prevent further unauthorized access or potential spread of malicious activity.
* Analyze the denied traffic logs to identify the source IP addresses and block them at the firewall or ACL level to prevent further attempts.
* Review and correct any misconfigurations in firewall rules or ACLs that may have contributed to the spike in denied traffic.
* Conduct a thorough investigation to determine if the spike is related to a denial-of-service attack and, if confirmed, engage with your internet service provider (ISP) for additional support and mitigation strategies.
* If malicious activity is suspected, escalate the incident to the security operations center (SOC) or incident response team for further analysis and response.
* Implement additional monitoring and alerting for similar patterns of denied traffic to enhance early detection of potential threats.
* Document the incident, including actions taken and lessons learned, to improve future response efforts and update incident response plans accordingly.


## Setup [_setup_1460]

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


