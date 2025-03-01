---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-mining-process-creation-event.html
---

# Suspicious Mining Process Creation Event [prebuilt-rule-8-17-4-suspicious-mining-process-creation-event]

Identifies service creation events of common mining services, possibly indicating the infection of a system with a cryptominer.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4420]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Mining Process Creation Event**

Cryptomining exploits system resources to mine cryptocurrency, often without user consent, impacting performance and security. Adversaries may deploy mining services on Linux systems, disguising them as legitimate processes. The detection rule identifies the creation of known mining service files, signaling potential unauthorized mining activity. By monitoring these specific file creation events, security teams can swiftly respond to and mitigate cryptomining threats.

**Possible investigation steps**

* Review the alert details to identify which specific mining service file was created, focusing on the file names listed in the query such as "aliyun.service" or "moneroocean_miner.service".
* Check the creation timestamp of the suspicious file to determine when the potential unauthorized mining activity began.
* Investigate the process that created the file by examining system logs or using process monitoring tools to identify the parent process and any associated command-line arguments.
* Analyze the system for additional indicators of compromise, such as unexpected network connections or high CPU usage, which may suggest active cryptomining.
* Verify the legitimacy of the file by comparing it against known hashes of legitimate services or using threat intelligence sources to identify known malicious files.
* Assess the system for any other suspicious activities or anomalies that may indicate further compromise or persistence mechanisms.

**False positive analysis**

* Legitimate administrative scripts or services may create files with names similar to known mining services. Verify the origin and purpose of such files before taking action.
* System administrators might deploy custom monitoring or management services that inadvertently match the file names in the detection rule. Review and whitelist these services if they are confirmed to be non-threatening.
* Automated deployment tools or scripts could create service files as part of routine operations. Ensure these tools are properly documented and exclude them from the detection rule if they are verified as safe.
* Some legitimate software installations might use generic service names that overlap with those flagged by the rule. Cross-check with software documentation and exclude these from alerts if they are confirmed to be benign.

**Response and remediation**

* Isolate the affected Linux system from the network to prevent further unauthorized mining activity and potential lateral movement by the adversary.
* Terminate any suspicious processes associated with the identified mining services, such as aliyun.service, moneroocean_miner.service, or others listed in the detection query.
* Remove the malicious service files from the system to prevent them from being restarted or reused by the attacker.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malware or persistence mechanisms.
* Review and update system and application patches to close any vulnerabilities that may have been exploited to deploy the mining services.
* Monitor network traffic for unusual outbound connections that may indicate communication with mining pools or command and control servers, and block these connections if detected.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_1264]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a Linux System:**

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


## Rule query [_rule_query_5412]

```js
file where host.os.type == "linux" and event.type == "creation" and event.action : ("creation", "file_create_event") and
file.name : ("aliyun.service", "moneroocean_miner.service", "c3pool_miner.service", "pnsd.service", "apache4.service", "pastebin.service", "xvf.service")
```

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

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)



