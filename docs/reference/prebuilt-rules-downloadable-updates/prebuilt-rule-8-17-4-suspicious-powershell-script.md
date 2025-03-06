---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-powershell-script.html
---

# Suspicious Powershell Script [prebuilt-rule-8-17-4-suspicious-powershell-script]

A machine learning job detected a PowerShell script with unusual data characteristics, such as obfuscation, that may be a characteristic of malicious PowerShell script text blocks.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)
* [https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration](https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Rule Type: ML
* Rule Type: Machine Learning
* Tactic: Execution
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4623]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Powershell Script**

PowerShell is a powerful scripting language used for task automation and configuration management in Windows environments. Adversaries often exploit its capabilities to execute malicious scripts, leveraging obfuscation to evade detection. The *Suspicious Powershell Script* detection rule employs machine learning to identify unusual script characteristics, such as obfuscation, indicating potential threats. By analyzing these anomalies, the rule aids in early threat detection and mitigation.

**Possible investigation steps**

* Review the alert details to identify the specific PowerShell script or command that triggered the detection, focusing on any obfuscated elements.
* Examine the source endpoint and user account associated with the alert to determine if the activity aligns with expected behavior or if it appears suspicious.
* Check the execution history on the affected endpoint for any other unusual or unauthorized PowerShell commands or scripts executed around the same time.
* Investigate the network activity from the source endpoint to identify any connections to known malicious IP addresses or domains.
* Correlate the alert with other security events or logs, such as antivirus alerts or firewall logs, to gather additional context and assess the potential impact.
* Consult threat intelligence sources to determine if the detected script or its components are associated with known malware or attack campaigns.

**False positive analysis**

* Legitimate administrative scripts may trigger the rule due to obfuscation techniques used for efficiency or security. Review the script’s purpose and source to determine its legitimacy.
* Automated deployment tools often use PowerShell scripts that appear obfuscated. Identify and whitelist these tools to prevent unnecessary alerts.
* Security software updates might use obfuscated scripts for protection against tampering. Verify the update source and add exceptions for known trusted vendors.
* Custom scripts developed in-house for specific tasks may use obfuscation for intellectual property protection. Document and exclude these scripts after confirming their safety.
* Regularly review and update the list of exceptions to ensure that only verified non-threatening scripts are excluded, maintaining the effectiveness of the detection rule.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of the potential threat and to contain any malicious activity.
* Terminate any suspicious PowerShell processes identified on the affected system to halt the execution of potentially harmful scripts.
* Conduct a thorough review of the PowerShell script logs and execution history on the affected system to identify any unauthorized or malicious commands executed.
* Restore the affected system from a known good backup if any malicious activity is confirmed, ensuring that the backup is free from compromise.
* Update and patch the affected system to the latest security standards to close any vulnerabilities that may have been exploited.
* Implement enhanced monitoring for PowerShell activity across the network, focusing on detecting obfuscation and unusual script characteristics.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Setup [_setup_1455]

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

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: PowerShell
    * ID: T1059.001
    * Reference URL: [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)



