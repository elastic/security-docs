---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-spike-in-network-traffic-to-a-country.html
---

# Spike in Network Traffic To a Country [prebuilt-rule-8-17-4-spike-in-network-traffic-to-a-country]

A machine learning job detected an unusually large spike in network activity to one destination country in the network logs. This could be due to unusually large amounts of reconnaissance or enumeration traffic. Data exfiltration activity may also produce such a surge in traffic to a destination country that does not normally appear in network traffic or business workflows. Malware instances and persistence mechanisms may communicate with command-and-control (C2) infrastructure in their country of origin, which may be an unusual destination country for the source network.

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

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4634]

**Triage and analysis**

**Investigating Spike in Network Traffic To a Country**

Monitoring network traffic for anomalies is a good methodology for uncovering various potentially suspicious activities. For example, data exfiltration or infected machines may communicate with a command-and-control (C2) server in another country your company doesn’t have business with.

This rule uses a machine learning job to detect a significant spike in the network traffic to a country, which can indicate reconnaissance or enumeration activities, an infected machine being used as a bot in a DDoS attack, or potentially data exfiltration.

**Possible investigation steps**

* Identify the specifics of the involved assets, such as role, criticality, and associated users.
* Investigate other alerts associated with the involved assets during the past 48 hours.
* Examine the data available and determine the exact users and processes involved in those connections.
* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Consider the time of day. If the user is a human (not a program or script), did the activity occurs during working hours?
* If this activity is suspicious, contact the account owner and confirm whether they are aware of it.

**False positive analysis**

* Understand the context of the connections by contacting the asset owners. If this activity is related to a new business process or newly implemented (approved) technology, consider adding exceptions — preferably with a combination of user and source conditions.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved hosts to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Consider implementing temporary network border rules to block or alert connections to the target country, if relevant.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_1466]

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


