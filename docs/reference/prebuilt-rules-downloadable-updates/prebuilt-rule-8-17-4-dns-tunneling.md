---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-dns-tunneling.html
---

# DNS Tunneling [prebuilt-rule-8-17-4-dns-tunneling]

A machine learning job detected unusually large numbers of DNS queries for a single top-level DNS domain, which is often used for DNS tunneling. DNS tunneling can be used for command-and-control, persistence, or data exfiltration activity. For example, dnscat tends to generate many DNS questions for a top-level domain as it uses the DNS protocol to tunnel data.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)

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

## Investigation guide [_investigation_guide_4608]

**Triage and analysis**

[TBC: QUOTE]
**Investigating DNS Tunneling**

DNS tunneling exploits the DNS protocol to covertly transmit data between a compromised system and an attacker-controlled server. Adversaries use it for stealthy command-and-control, persistence, or data exfiltration by embedding data within DNS queries. The detection rule leverages machine learning to identify anomalies, such as an unusually high volume of DNS queries to a single domain, indicating potential tunneling activity.

**Possible investigation steps**

* Review the DNS query logs to identify the specific top-level domain generating the unusually high volume of queries. This can help pinpoint the potential source of tunneling activity.
* Analyze the source IP addresses associated with the DNS queries to determine if they originate from known or suspicious hosts within the network.
* Check for any recent changes or anomalies in the network traffic patterns related to the identified domain, which might indicate tunneling or exfiltration attempts.
* Investigate the history of the identified domain to assess its reputation and any known associations with malicious activities or threat actors.
* Correlate the DNS query activity with other security events or alerts in the network to identify any related suspicious behavior or indicators of compromise.

**False positive analysis**

* High volume of DNS queries from legitimate software updates or patch management systems can trigger false positives. Users should identify and whitelist domains associated with trusted update services.
* Content delivery networks (CDNs) often generate numerous DNS queries due to their distributed nature. Exclude known CDN domains from the analysis to reduce false positives.
* Internal network monitoring tools that rely on DNS for service discovery may cause an increase in DNS queries. Consider excluding these internal domains if they are verified as non-threatening.
* Some cloud services use DNS for load balancing and may result in high query volumes. Users should review and whitelist these domains if they are confirmed to be safe.
* Automated scripts or applications that frequently query DNS for legitimate purposes can be excluded by identifying their specific patterns and adding them to an exception list.

**Response and remediation**

* Isolate the affected system from the network to prevent further data exfiltration or command-and-control communication.
* Conduct a thorough analysis of DNS logs to identify the specific domain involved in the tunneling activity and block it at the network perimeter.
* Review and terminate any suspicious processes or services running on the compromised system that may be associated with the tunneling activity.
* Reset credentials and review access permissions for accounts that were active on the compromised system to prevent unauthorized access.
* Escalate the incident to the security operations center (SOC) for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring for DNS traffic to detect similar tunneling activities in the future, focusing on high-frequency queries to single domains.
* Coordinate with IT and security teams to apply necessary patches and updates to the affected system to close any vulnerabilities exploited by the attacker.


## Setup [_setup_1440]

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

    * Name: Protocol Tunneling
    * ID: T1572
    * Reference URL: [https://attack.mitre.org/techniques/T1572/](https://attack.mitre.org/techniques/T1572/)



