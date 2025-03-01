---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/openssl-password-hash-generation.html
---

# OpenSSL Password Hash Generation [openssl-password-hash-generation]

This rule detects the usage of the `openssl` binary to generate password hashes on Linux systems. The `openssl` command is a cryptographic utility that can be used to generate password hashes. Attackers may use `openssl` to generate password hashes for new user accounts or to change the password of existing accounts, which can be leveraged to maintain persistence on a Linux system.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

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
* Tactic: Persistence
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_609]

**Triage and analysis**

[TBC: QUOTE]
**Investigating OpenSSL Password Hash Generation**

OpenSSL is a robust cryptographic toolkit used for secure communications and data protection, including generating password hashes. Adversaries may exploit OpenSSL to create hashes for unauthorized user accounts or modify existing ones, aiding in persistent access to Linux systems. The detection rule identifies suspicious OpenSSL executions by monitoring specific process actions and arguments, flagging potential misuse for further investigation.

**Possible investigation steps**

* Review the process execution details to confirm the presence of the "openssl" command with the "passwd" argument, as this indicates an attempt to generate a password hash.
* Identify the user account associated with the process execution to determine if the action was performed by a legitimate user or a potential adversary.
* Check the system logs and user activity around the time of the alert to identify any suspicious behavior or unauthorized access attempts.
* Investigate any recent changes to user accounts on the system, focusing on new account creations or password modifications that coincide with the alert.
* Correlate the alert with other security events or alerts from the same host to identify patterns or additional indicators of compromise.
* Assess the risk and impact of the detected activity by considering the context of the system and its role within the organization, as well as any potential data exposure or system access implications.

**False positive analysis**

* Routine administrative tasks may trigger the rule when system administrators use OpenSSL to generate password hashes for legitimate user account management. To handle this, create exceptions for specific administrator accounts or processes that are known to perform these tasks regularly.
* Automated scripts for user account provisioning or maintenance that utilize OpenSSL for password hashing can also cause false positives. Identify these scripts and exclude their execution paths or associated user accounts from the rule.
* Security tools or compliance checks that periodically verify password strength or integrity using OpenSSL might be flagged. Review these tools and whitelist their operations to prevent unnecessary alerts.
* Development environments where OpenSSL is used for testing password hashing functions can generate alerts. Exclude these environments or specific test accounts from monitoring to reduce noise.
* Scheduled tasks or cron jobs that involve OpenSSL for password management purposes should be identified and excluded if they are part of regular system operations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious OpenSSL processes identified by the detection rule to halt ongoing unauthorized password hash generation.
* Conduct a thorough review of user accounts on the affected system to identify any unauthorized accounts or changes to existing accounts, and revert any unauthorized modifications.
* Change passwords for all user accounts on the affected system, especially those with elevated privileges, to ensure that any compromised credentials are no longer valid.
* Implement additional monitoring on the affected system to detect any further unauthorized use of OpenSSL or similar tools, focusing on process execution and command-line arguments.
* Escalate the incident to the security operations team for a comprehensive investigation to determine the root cause and scope of the breach, and to assess potential impacts on other systems.
* Review and update access controls and authentication mechanisms to enhance security and prevent similar incidents in the future, ensuring that only authorized users can perform sensitive operations.


## Setup [_setup_395]

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


## Rule query [_rule_query_651]

```js
process where host.os.type == "linux" and event.type == "start" and
event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed") and process.name == "openssl"
and process.args == "passwd"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create Account
    * ID: T1136
    * Reference URL: [https://attack.mitre.org/techniques/T1136/](https://attack.mitre.org/techniques/T1136/)

* Sub-technique:

    * Name: Local Account
    * ID: T1136.001
    * Reference URL: [https://attack.mitre.org/techniques/T1136/001/](https://attack.mitre.org/techniques/T1136/001/)



