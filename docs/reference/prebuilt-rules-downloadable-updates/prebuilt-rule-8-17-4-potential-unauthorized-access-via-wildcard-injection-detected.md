---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-potential-unauthorized-access-via-wildcard-injection-detected.html
---

# Potential Unauthorized Access via Wildcard Injection Detected [prebuilt-rule-8-17-4-potential-unauthorized-access-via-wildcard-injection-detected]

This rule monitors for the execution of the "chown" and "chmod" commands with command line flags that could indicate a wildcard injection attack. Linux wildcard injection is a type of security vulnerability where attackers manipulate commands or input containing wildcards (e.g., *, ?, []) to execute unintended operations or access sensitive data by tricking the system into interpreting the wildcard characters in unexpected ways.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
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

**References**:

* [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Tactic: Credential Access
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 106

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4512]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Unauthorized Access via Wildcard Injection Detected**

In Linux environments, commands like `chown` and `chmod` are used to change file ownership and permissions. Adversaries may exploit wildcard characters in these commands to escalate privileges or access sensitive data by executing unintended operations. The detection rule identifies suspicious use of these commands with recursive flags and wildcard references, signaling potential misuse aimed at privilege escalation or unauthorized data access.

**Possible investigation steps**

* Review the process execution details to confirm the presence of the "chown" or "chmod" command with the "-R" flag and wildcard usage in the arguments, as indicated by the query fields process.name, process.args, and event.action.
* Examine the user account associated with the process execution to determine if it has the necessary permissions to perform such operations and assess if the account has been compromised.
* Check the command execution history and related logs to identify any preceding or subsequent suspicious activities that might indicate a broader attack pattern or unauthorized access attempts.
* Investigate the source and destination of the command execution by analyzing network logs and connections to determine if the activity originated from a known or unknown IP address or host.
* Correlate this event with other alerts or anomalies in the system to identify potential patterns or coordinated attacks, focusing on privilege escalation or credential access attempts as suggested by the rule’s tags and threat information.

**False positive analysis**

* Routine administrative tasks using chown or chmod with recursive flags may trigger the rule. To manage this, identify and whitelist specific scripts or users that regularly perform these tasks without security risks.
* Automated system maintenance processes that involve changing file permissions or ownership across directories can be mistaken for malicious activity. Exclude these processes by specifying their command patterns or associated user accounts in the monitoring system.
* Backup operations that involve copying and setting permissions on large sets of files might be flagged. To prevent this, configure exceptions for known backup tools or scripts that use these commands in a controlled manner.
* Development environments where developers frequently change file permissions for testing purposes can generate false positives. Implement user-based exceptions for development teams to reduce unnecessary alerts.
* System updates or package installations that modify file permissions as part of their normal operation may be detected. Create exceptions for trusted package managers or update processes to avoid false alarms.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or data exfiltration.
* Terminate any suspicious processes identified as running the `chown` or `chmod` commands with wildcard injections to halt potential privilege escalation activities.
* Conduct a thorough review of system logs and command histories to identify any unauthorized changes made to file permissions or ownership and revert them to their original state.
* Reset credentials and review access permissions for users on the affected system to ensure no unauthorized access persists.
* Implement file integrity monitoring to detect unauthorized changes to critical files and directories in the future.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Update and patch the affected system to address any vulnerabilities that may have been exploited during the attack, ensuring all security updates are applied.


## Setup [_setup_1345]

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


## Rule query [_rule_query_5504]

```js
process where host.os.type == "linux" and event.type == "start" and
  event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started") and
  process.name in ("chown", "chmod") and process.args == "-R" and process.args : "--reference=*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: /etc/passwd and /etc/shadow
    * ID: T1003.008
    * Reference URL: [https://attack.mitre.org/techniques/T1003/008/](https://attack.mitre.org/techniques/T1003/008/)



