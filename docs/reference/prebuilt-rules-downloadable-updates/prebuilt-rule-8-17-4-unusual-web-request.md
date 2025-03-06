---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-web-request.html
---

# Unusual Web Request [prebuilt-rule-8-17-4-unusual-web-request]

A machine learning job detected a rare and unusual URL that indicates unusual web browsing activity. This can be due to initial access, persistence, command-and-control, or exfiltration activity. For example, in a strategic web compromise or watering hole attack, when a trusted website is compromised to target a particular sector or organization, targeted users may receive emails with uncommon URLs for trusted websites. These URLs can be used to download and run a payload. When malware is already running, it may send requests to uncommon URLs on trusted websites the malware uses for command-and-control communication. When rare URLs are observed being requested for a local web server by a remote source, these can be due to web scanning, enumeration or attack traffic, or they can be due to bots and web scrapers which are part of common Internet background traffic.

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

## Investigation guide [_investigation_guide_4610]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Web Request**

The *Unusual Web Request* detection leverages machine learning to identify rare URLs that deviate from typical web activity, potentially signaling malicious actions like initial access or data exfiltration. Adversaries exploit trusted sites by embedding uncommon URLs for payload delivery or command-and-control. This rule flags such anomalies, aiding in early threat detection and response.

**Possible investigation steps**

* Review the alert details to identify the specific rare URL that triggered the detection and note any associated IP addresses or domains.
* Check historical logs to determine if the rare URL has been accessed previously and identify any patterns or trends in its usage.
* Investigate the source of the request by examining the user agent, referrer, and originating IP address to assess whether it aligns with known legitimate traffic or appears suspicious.
* Analyze the destination of the URL to determine if it is associated with known malicious activity or if it has been flagged in threat intelligence databases.
* Correlate the unusual web request with other security events or alerts to identify potential connections to broader attack campaigns or ongoing threats.
* Assess the impacted systems or users to determine if there are any signs of compromise, such as unexpected processes, network connections, or data exfiltration attempts.
* Consider reaching out to the user or system owner to verify if the access to the rare URL was intentional and legitimate, providing additional context for the investigation.

**False positive analysis**

* Web scraping tools and bots can trigger false positives by making requests to uncommon URLs as part of routine internet background traffic.
* Legitimate web scanning or enumeration activities by security teams may be flagged; these should be reviewed and whitelisted if verified as non-threatening.
* Automated processes or scripts that access rare URLs for legitimate business purposes can be excluded by identifying and documenting these activities.
* Frequent access to uncommon URLs by trusted internal applications or services should be monitored and added to exception lists to prevent unnecessary alerts.
* Regularly review and update the list of excluded URLs to ensure it reflects current legitimate activities and does not inadvertently allow malicious traffic.

**Response and remediation**

* Isolate the affected system from the network to prevent further communication with the suspicious URL and potential data exfiltration.
* Conduct a thorough scan of the isolated system using updated antivirus and anti-malware tools to identify and remove any malicious payloads or software.
* Review and block the identified unusual URL at the network perimeter to prevent other systems from accessing it.
* Analyze network logs to identify any other systems that may have communicated with the suspicious URL and apply similar containment measures.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if the threat is part of a larger attack campaign.
* Implement enhanced monitoring for similar unusual web requests across the network to detect and respond to potential threats more quickly in the future.
* Review and update firewall and intrusion detection/prevention system (IDS/IPS) rules to better detect and block uncommon URLs associated with command-and-control activities.


## Setup [_setup_1442]

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

    * Name: Web Protocols
    * ID: T1071.001
    * Reference URL: [https://attack.mitre.org/techniques/T1071/001/](https://attack.mitre.org/techniques/T1071/001/)



