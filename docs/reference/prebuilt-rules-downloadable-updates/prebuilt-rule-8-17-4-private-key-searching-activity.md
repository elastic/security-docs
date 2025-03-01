---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-private-key-searching-activity.html
---

# Private Key Searching Activity [prebuilt-rule-8-17-4-private-key-searching-activity]

This rule detects private key searching activity on Linux systems. Searching for private keys can be an indication of an attacker attempting to escalate privileges or exfiltrate sensitive information.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*
* endgame-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Discovery
* Data Source: Elastic Defend
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Data Source: Elastic Endgame
* Resources: Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4374]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Private Key Searching Activity**

In Linux environments, private keys are crucial for secure communications and authentication. Adversaries may exploit this by searching for private keys to gain unauthorized access or escalate privileges. The detection rule identifies suspicious use of the *find* command targeting key files in sensitive directories, signaling potential malicious intent. This proactive monitoring helps mitigate risks associated with unauthorized key access.

**Possible investigation steps**

* Review the process details to confirm the *find* command was executed with parameters targeting private key files, as indicated by the command line containing patterns like "**id_dsa**", "**id_rsa**", etc., and directories such as "/home/", "/etc/ssh", or "/root/".
* Identify the user account associated with the process to determine if the activity aligns with expected behavior for that user or if it suggests potential compromise.
* Check the process’s parent process to understand the context in which the *find* command was executed, which may provide insights into whether this was part of a legitimate script or an unauthorized action.
* Investigate any recent login activity or changes in user privileges for the account involved to assess if there has been any unauthorized access or privilege escalation.
* Examine system logs and other security alerts around the time of the event to identify any correlated suspicious activities or anomalies that might indicate a broader attack campaign.

**False positive analysis**

* System administrators or automated scripts may use the *find* command to locate private keys for legitimate maintenance tasks. To handle this, create exceptions for known administrative accounts or scripts that regularly perform these actions.
* Backup processes might search for private keys as part of routine data protection activities. Identify and exclude these processes by specifying their unique command-line patterns or process IDs.
* Security audits or compliance checks often involve scanning for private keys to ensure proper security measures are in place. Exclude these activities by recognizing the specific tools or scripts used during audits.
* Developers or DevOps teams may search for private keys during application deployment or configuration. Establish a list of trusted users or processes involved in these operations and exclude them from triggering alerts.
* Automated configuration management tools like Ansible or Puppet might search for keys as part of their operations. Identify these tools and exclude their specific command-line patterns to prevent false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified by the detection rule, particularly those involving the *find* command searching for private keys.
* Conduct a thorough review of access logs and process execution history to identify any unauthorized access or privilege escalation attempts.
* Change all potentially compromised private keys and associated credentials, ensuring new keys are securely generated and stored.
* Implement stricter access controls and permissions on directories containing private keys to limit exposure to unauthorized users.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Enhance monitoring and alerting for similar activities by ensuring that detection rules are tuned to capture variations of the *find* command targeting sensitive files.


## Setup [_setup_1221]

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


## Rule query [_rule_query_5366]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and process.name == "find" and
  process.command_line like ("*id_dsa*", "*id_rsa*", "*id_ed*", "*id_ecdsa*", "*id_xmss*", "*id_dh*") and
  process.command_line like ("*/home/*", "*/etc/ssh*", "*/root/*", "/")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)



