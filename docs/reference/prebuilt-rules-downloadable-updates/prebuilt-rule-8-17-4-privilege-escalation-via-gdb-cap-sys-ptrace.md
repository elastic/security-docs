---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-privilege-escalation-via-gdb-cap-sys-ptrace.html
---

# Privilege Escalation via GDB CAP_SYS_PTRACE [prebuilt-rule-8-17-4-privilege-escalation-via-gdb-cap-sys-ptrace]

Identifies instances where GDB (granted the CAP_SYS_PTRACE capability) is executed, after which the user’s access is elevated to UID/GID 0 (root). In Linux, the CAP_SYS_PTRACE capability grants a process the ability to use the ptrace system call, which is typically used for debugging and allows the process to trace and control other processes. Attackers may leverage this capability to hook and inject into a process that is running with root permissions in order to escalate their privileges to root.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

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
* Tactic: Privilege Escalation
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4518]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Privilege Escalation via GDB CAP_SYS_PTRACE**

The CAP_SYS_PTRACE capability in Linux allows processes to trace and control other processes, a feature primarily used for debugging. Adversaries can exploit this by using GDB with this capability to inject code into processes running as root, thereby escalating privileges. The detection rule identifies such abuse by monitoring sequences where GDB is executed with CAP_SYS_PTRACE, followed by a process running as root, indicating potential privilege escalation.

**Possible investigation steps**

* Review the alert details to identify the specific host and process entity ID where the GDB execution with CAP_SYS_PTRACE was detected.
* Examine the process tree on the affected host to determine the parent process of GDB and any child processes it may have spawned, focusing on any processes running as root.
* Check the user account associated with the GDB execution to verify if it is a legitimate user and assess if there are any indications of compromise or misuse.
* Investigate the timeline of events around the alert to identify any preceding or subsequent suspicious activities, such as unauthorized access attempts or changes in user privileges.
* Analyze system logs and audit records for any signs of unauthorized access or privilege escalation attempts, particularly focusing on the time window specified by the maxspan of 1 minute in the query.
* Correlate the findings with other security alerts or incidents on the same host to determine if this event is part of a larger attack campaign.

**False positive analysis**

* Development environments where GDB is frequently used for legitimate debugging purposes may trigger false positives. To mitigate this, consider excluding specific user accounts or processes that are known to use GDB regularly for debugging.
* Automated testing systems that utilize GDB for testing applications with elevated privileges might be flagged. Implement exceptions for these systems by identifying and excluding their specific process names or user IDs.
* Security tools or monitoring solutions that use GDB with CAP_SYS_PTRACE for legitimate monitoring or analysis tasks can cause false alerts. Review and whitelist these tools by their process names or associated user accounts.
* System administrators or developers who have legitimate reasons to use GDB with elevated capabilities should be identified, and their activities should be excluded from the rule to prevent unnecessary alerts.
* Scheduled maintenance scripts that involve GDB for system diagnostics or performance tuning may be misinterpreted as malicious. Exclude these scripts by their execution schedule or specific identifiers.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious processes identified as running with elevated privileges, especially those involving GDB with CAP_SYS_PTRACE.
* Revoke CAP_SYS_PTRACE capability from non-essential users and processes to limit potential abuse.
* Conduct a thorough review of user accounts and permissions on the affected system to ensure no unauthorized privilege escalations have occurred.
* Restore the affected system from a known good backup if any unauthorized changes or code injections are detected.
* Monitor the affected and related systems for any signs of persistence mechanisms or further malicious activity.
* Report the incident to the appropriate internal security team or authority for further investigation and potential escalation if necessary.


## Setup [_setup_1350]

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


## Rule query [_rule_query_5510]

```js
sequence by host.id, process.entry_leader.entity_id with maxspan=1m
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and process.name == "gdb" and
   (process.thread.capabilities.effective : "CAP_SYS_PTRACE" or process.thread.capabilities.permitted : "CAP_SYS_PTRACE") and
   user.id != "0"]
  [process where host.os.type == "linux" and event.type == "start" and event.action == "exec" and
   process.name != null and user.id == "0"]
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

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)



