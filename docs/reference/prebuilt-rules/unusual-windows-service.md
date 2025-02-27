---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-windows-service.html
---

# Unusual Windows Service [unusual-windows-service]

A machine learning job detected an unusual Windows service, This can indicate execution of unauthorized services, malware, or persistence mechanisms. In corporate Windows environments, hosts do not generally run many rare or unique services. This job helps detect malware and persistence mechanisms that have been installed and run as a service.

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
* OS: Windows
* Use Case: Threat Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1167]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Windows Service**

Windows services are crucial for running background processes and applications. Adversaries exploit this by creating or modifying services to maintain persistence or execute unauthorized actions. The *Unusual Windows Service* detection rule leverages machine learning to identify atypical services, flagging potential threats by comparing against known service patterns, thus aiding in early threat detection and response.

**Possible investigation steps**

* Review the details of the detected unusual Windows service, including the service name, path, and any associated executables, to determine if it aligns with known legitimate services or appears suspicious.
* Check the creation and modification timestamps of the service to identify if it was recently added or altered, which could indicate unauthorized activity.
* Investigate the user account under which the service is running to assess if it has the necessary permissions and if the account has been compromised or misused.
* Cross-reference the service with known threat intelligence databases to see if it matches any known malware or persistence mechanisms.
* Analyze the network activity and connections associated with the service to identify any unusual or unauthorized communication patterns.
* Examine the host’s event logs for any related entries that could provide additional context or evidence of malicious activity, such as failed login attempts or privilege escalation events.

**False positive analysis**

* Legitimate software installations or updates may create new services that are flagged as unusual. Users should verify the source and purpose of the service before excluding it.
* Custom in-house applications often run unique services that can trigger alerts. Document these services and create exceptions to prevent future false positives.
* IT administrative tools might install services for management purposes. Confirm these tools are authorized and add them to an exception list if they are frequently flagged.
* Temporary services used for troubleshooting or testing can be mistaken for threats. Ensure these are removed after use or excluded if they are part of regular operations.
* Scheduled tasks that create services for specific operations might be flagged. Review these tasks and exclude them if they are part of normal business processes.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent potential lateral movement or data exfiltration by the unauthorized service.
* Terminate the unusual Windows service identified by the alert to stop any ongoing malicious activity.
* Conduct a thorough analysis of the service’s executable and associated files to determine if they are malicious. Use endpoint detection and response (EDR) tools to assist in this analysis.
* Remove any malicious files or executables associated with the service from the system to ensure complete eradication of the threat.
* Restore the affected system from a known good backup if the service has caused significant changes or damage to the system.
* Monitor the system and network for any signs of re-infection or similar unusual service activity, using enhanced logging and alerting mechanisms.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the need for broader organizational response measures.


## Setup [_setup_739]

**Setup**

This rule requires the installation of associated Machine Learning jobs, as well as data coming in from one of the following integrations: - Elastic Defend - Windows

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

**Windows Integration Setup**

The Windows integration allows you to monitor the Windows OS, services, applications, and more.

**The following steps should be executed in order to add the Elastic Agent System integration "windows" to your system:**

* Go to the Kibana home page and click “Add integrations”.
* In the query bar, search for “Windows” and select the integration to see more details about it.
* Click “Add Windows”.
* Configure the integration name and optionally add a description.
* Review optional and advanced settings accordingly.
* Add the newly installed “windows” to an existing or a new agent policy, and deploy the agent on your system from which windows log files are desirable.
* Click “Save and Continue”.
* For more details on the integration refer to the [helper guide](https://docs.elastic.co/integrations/windows).

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Windows Service
    * ID: T1543.003
    * Reference URL: [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)



