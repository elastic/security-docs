---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-dumping-account-hashes-via-built-in-commands.html
---

# Dumping Account Hashes via Built-In Commands [prebuilt-rule-8-17-4-dumping-account-hashes-via-built-in-commands]

Identifies the execution of macOS built-in commands used to dump user account hashes. Adversaries may attempt to dump credentials to obtain account login information in the form of a hash. These hashes can be cracked or leveraged for lateral movement.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://apple.stackexchange.com/questions/186893/os-x-10-9-where-are-password-hashes-stored](https://apple.stackexchange.com/questions/186893/os-x-10-9-where-are-password-hashes-stored)
* [https://www.unix.com/man-page/osx/8/mkpassdb/](https://www.unix.com/man-page/osx/8/mkpassdb/)

**Tags**:

* Domain: Endpoint
* OS: macOS
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4546]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Dumping Account Hashes via Built-In Commands**

In macOS environments, built-in commands like `defaults` and `mkpassdb` can be exploited by adversaries to extract user account hashes, which are crucial for credential access. These hashes, once obtained, can be cracked to reveal passwords or used for lateral movement within a network. The detection rule identifies suspicious process executions involving these commands and specific arguments, signaling potential credential dumping activities.

**Possible investigation steps**

* Review the process execution details to confirm the presence of the `defaults` or `mkpassdb` commands with arguments like `ShadowHashData` or `-dump`, as these are indicative of credential dumping attempts.
* Identify the user account associated with the process execution to determine if the activity aligns with expected behavior for that user or if it appears suspicious.
* Check the historical activity of the involved user account and the host to identify any patterns or anomalies that could suggest unauthorized access or lateral movement.
* Investigate any network connections or subsequent processes initiated by the suspicious process to assess potential data exfiltration or further malicious actions.
* Correlate the event with other security alerts or logs from the same host or user account to build a comprehensive timeline of the activity and assess the scope of the potential compromise.

**False positive analysis**

* System administrators or security tools may legitimately use the `defaults` or `mkpassdb` commands for system maintenance or auditing purposes. To manage these, create exceptions for known administrative accounts or tools that regularly execute these commands.
* Automated scripts or management software might invoke these commands as part of routine operations. Identify and whitelist these scripts or software to prevent unnecessary alerts.
* Developers or IT personnel might use these commands during testing or development phases. Establish a process to temporarily exclude these activities by setting up time-bound exceptions for specific user accounts or devices.
* Security assessments or penetration tests could trigger this rule. Coordinate with security teams to schedule and document these activities, allowing for temporary rule adjustments during the testing period.

**Response and remediation**

* Immediately isolate the affected macOS system from the network to prevent further lateral movement or data exfiltration.
* Terminate any suspicious processes identified as using the `defaults` or `mkpassdb` commands with the specified arguments to halt ongoing credential dumping activities.
* Conduct a thorough review of user accounts on the affected system to identify any unauthorized access or changes, focusing on accounts with elevated privileges.
* Reset passwords for all potentially compromised accounts, especially those with administrative access, and enforce strong password policies.
* Analyze system logs and network traffic to identify any additional systems that may have been accessed using the compromised credentials, and apply similar containment measures.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the full scope of the breach.
* Implement enhanced monitoring and alerting for similar suspicious activities across the network to detect and respond to future attempts promptly.


## Setup [_setup_1378]

**Setup**

This rule requires data coming in from Elastic Defend.

**Elastic Defend Integration Setup**

Elastic Defend is integrated into the Elastic Agent using Fleet. Upon configuration, the integration allows the Elastic Agent to monitor events on your host and send data to the Elastic Security app.

**Prerequisite Requirements:**

* Fleet is required for Elastic Defend.
* To configure Fleet Server refer to the [documentation](docs-content://reference/ingestion-tools/fleet/fleet-server.md).

**The following steps should be executed in order to add the Elastic Defend integration on a macOS System:**

* Go to the Kibana home page and click "Add integrations".
* In the query bar, search for "Elastic Defend" and select the integration to see more details about it.
* Click "Add Elastic Defend".
* Configure the integration name and optionally add a description.
* Select the type of environment you want to protect, for MacOS it is recommended to select "Traditional Endpoints".
* Select a configuration preset. Each preset comes with different default settings for Elastic Agent, you can further customize these later by configuring the Elastic Defend integration policy. [Helper guide](docs-content://solutions/security/configure-elastic-defend/configure-an-integration-policy-for-elastic-defend.md).
* We suggest selecting "Complete EDR (Endpoint Detection and Response)" as a configuration setting, that provides "All events; all preventions"
* Enter a name for the agent policy in "New agent policy name". If other agent policies already exist, you can click the "Existing hosts" tab and select an existing policy instead. For more details on Elastic Agent configuration settings, refer to the [helper guide](docs-content://reference/ingestion-tools/fleet/agent-policy.md).
* Click "Save and Continue".
* To complete the integration, select "Add Elastic Agent to your hosts" and continue to the next section to install the Elastic Agent on your hosts. For more details on Elastic Defend refer to the [helper guide](docs-content://solutions/security/configure-elastic-defend/install-elastic-defend.md).


## Rule query [_rule_query_5538]

```js
event.category:process and host.os.type:macos and event.type:start and
 process.name:(defaults or mkpassdb) and process.args:(ShadowHashData or "-dump")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)



