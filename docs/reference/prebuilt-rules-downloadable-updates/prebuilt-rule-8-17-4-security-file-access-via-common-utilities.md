---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-security-file-access-via-common-utilities.html
---

# Security File Access via Common Utilities [prebuilt-rule-8-17-4-security-file-access-via-common-utilities]

This rule detects sensitive security file access via common utilities on Linux systems. Adversaries may attempt to read from sensitive files using common utilities to gather information about the system and its security configuration.

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

## Investigation guide [_investigation_guide_4378]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Security File Access via Common Utilities**

In Linux environments, common utilities like `cat`, `grep`, and `less` are essential for file manipulation and viewing. Adversaries exploit these tools to access sensitive security files, aiming to gather system and security configuration data. The detection rule identifies suspicious use of these utilities by monitoring process execution patterns and arguments, flagging attempts to access critical security files, thus helping to thwart potential reconnaissance activities.

**Possible investigation steps**

* Review the process execution details to identify the specific utility used (e.g., cat, grep, less) and the exact file path accessed, as indicated by the process.name and process.args fields.
* Check the user account associated with the process execution to determine if the access was performed by a legitimate user or a potentially compromised account.
* Investigate the timing and frequency of the access attempt to assess whether it aligns with normal user behavior or indicates suspicious activity.
* Correlate the alert with other security events or logs from the same host to identify any preceding or subsequent suspicious activities, such as unauthorized logins or privilege escalation attempts.
* Examine the host’s recent changes or updates to security configurations or user permissions that might explain the access attempt.
* If possible, contact the user or system owner to verify whether the access was intentional and authorized, providing additional context for the investigation.

**False positive analysis**

* System administrators or automated scripts may frequently access security files for legitimate maintenance or configuration purposes. To handle this, create exceptions for known administrative accounts or specific scripts that regularly perform these actions.
* Security monitoring tools or compliance checks might trigger the rule when scanning security files. Identify these tools and exclude their processes from the rule to prevent unnecessary alerts.
* Backup processes that involve copying or reading security files can be mistaken for suspicious activity. Exclude backup software processes or scheduled tasks that are known to perform these operations.
* Developers or DevOps personnel accessing configuration files for application deployment or troubleshooting might trigger the rule. Establish a list of trusted users or roles and exclude their access patterns from detection.
* Regular system updates or package management operations may involve accessing security-related files. Recognize these update processes and exclude them to avoid false positives during routine maintenance.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified by the detection rule to halt potential reconnaissance activities.
* Conduct a thorough review of the accessed files to determine if any sensitive information was exposed or altered.
* Change credentials and access tokens for any compromised accounts, especially those related to AWS, GCP, or Azure, to prevent unauthorized access.
* Implement stricter access controls and permissions on sensitive security files to limit exposure to only necessary users and processes.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on the broader network.
* Enhance monitoring and logging for similar activities to improve detection and response times for future incidents.


## Setup [_setup_1225]

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


## Rule query [_rule_query_5370]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2") and
  process.name in ("cat", "grep", "less", "more", "strings", "awk", "find", "xargs") and
  process.args like (
    "/etc/security/*", "/etc/pam.d/*", "/etc/login.defs", "/lib/security/*", "/lib64/security/*",
    "/usr/lib/security/*", "/usr/lib64/security/*", "/usr/lib/x86_64-linux-gnu/security/*",
    "/home/*/.aws/credentials", "/home/*/.aws/config", "/home/*/.config/gcloud/*credentials.json",
    "/home/*/.config/gcloud/configurations/config_default", "/home/*/.azure/accessTokens.json",
    "/home/*/.azure/azureProfile.json"
  ) and
not process.parent.name in ("wazuh-modulesd", "lynis")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)



