---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-sudo-token-manipulation-via-process-injection.html
---

# Potential Sudo Token Manipulation via Process Injection [potential-sudo-token-manipulation-via-process-injection]

This rule detects potential sudo token manipulation attacks through process injection by monitoring the use of a debugger (gdb) process followed by a successful uid change event during the execution of the sudo process. A sudo token manipulation attack is performed by injecting into a process that has a valid sudo token, which can then be used by attackers to activate their own sudo token. This attack requires ptrace to be enabled in conjunction with the existence of a living process that has a valid sudo token with the same uid as the current user.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/nongiach/sudo_inject](https://github.com/nongiach/sudo_inject)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 108

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_780]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Potential Sudo Token Manipulation via Process Injection**

In Linux environments, process injection can be exploited by adversaries to manipulate sudo tokens, allowing unauthorized privilege escalation. Attackers may use debugging tools like gdb to inject code into processes with valid sudo tokens, leveraging ptrace capabilities. The detection rule identifies this threat by monitoring for gdb execution followed by a uid change in the sudo process, indicating potential token manipulation.

**Possible investigation steps**

* Review the alert details to identify the specific host and process session leader entity ID involved in the potential sudo token manipulation.
* Examine the process tree on the affected host to trace the parent and child processes of the gdb execution, focusing on any unusual or unauthorized processes.
* Check the system logs for any recent sudo commands executed by the user associated with the gdb process to determine if there were any unauthorized privilege escalations.
* Investigate the user account associated with the gdb process to verify if it has legitimate reasons to use debugging tools and if it has been compromised.
* Analyze the timing and context of the uid change event in the sudo process to assess if it aligns with legitimate administrative activities or if it appears suspicious.
* Review the system’s ptrace settings to ensure they are configured securely and assess if there have been any recent changes that could have enabled this attack vector.

**False positive analysis**

* Debugging activities by developers or system administrators using gdb for legitimate purposes can trigger this rule. To manage this, create exceptions for specific user IDs or groups known to perform regular debugging tasks.
* Automated scripts or maintenance tools that utilize gdb for process analysis might cause false positives. Identify these scripts and exclude their associated process names or paths from the rule.
* System monitoring or security tools that perform uid changes as part of their normal operation could be mistaken for malicious activity. Review and whitelist these tools by their process names or specific user IDs.
* Training or testing environments where sudo and gdb are used frequently for educational purposes may generate alerts. Consider excluding these environments by host ID or network segment to reduce noise.
* Scheduled tasks or cron jobs that involve gdb and sudo processes might inadvertently match the rule criteria. Analyze these tasks and exclude them based on their execution times or specific process attributes.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or privilege escalation.
* Terminate any suspicious gdb and sudo processes identified in the alert to stop ongoing process injection attempts.
* Conduct a thorough review of the affected system’s process and user activity logs to identify any unauthorized changes or access patterns.
* Reset credentials and sudo tokens for all users on the affected system to prevent further exploitation using compromised tokens.
* Apply security patches and updates to the affected system to address any vulnerabilities that may have been exploited.
* Re-enable ptrace restrictions if they were previously disabled, to limit the ability of attackers to perform process injection.
* Escalate the incident to the security operations team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_504]

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


## Rule query [_rule_query_828]

```js
sequence by host.id, process.session_leader.entity_id with maxspan=15s
[ process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
  process.name == "gdb" and process.user.id != "0" and process.group.id != "0" ]
[ process where host.os.type == "linux" and event.action == "uid_change" and event.type == "change" and
  process.name == "sudo" and process.user.id == "0" and process.group.id == "0" ]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)

* Sub-technique:

    * Name: Ptrace System Calls
    * ID: T1055.008
    * Reference URL: [https://attack.mitre.org/techniques/T1055/008/](https://attack.mitre.org/techniques/T1055/008/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Sudo and Sudo Caching
    * ID: T1548.003
    * Reference URL: [https://attack.mitre.org/techniques/T1548/003/](https://attack.mitre.org/techniques/T1548/003/)



